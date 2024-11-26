#include "ptl_am_iface.h"
#include "ptl_am_ep.h"
#include "ptl_am_md.h"

static uct_iface_ops_t uct_ptl_am_iface_tl_ops;
static uct_ptl_iface_ops_t uct_ptl_am_iface_ops;

ucs_config_field_t uct_ptl_am_iface_config_table[] = {
    {"", "", NULL, ucs_offsetof(uct_ptl_am_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_ptl_iface_config_table)},

    {NULL}};

static inline void uct_ptl_am_copy_short(const void *src, size_t length,
                                         uint64_t hdr, void *dest) {
  *(uint64_t *)dest = hdr;
  memcpy(UCS_PTR_BYTE_OFFSET(dest, sizeof(uint64_t)), src, length);
}

static ucs_status_t uct_ptl_am_iface_handle_ev(uct_ptl_iface_t *iface,
                                               ptl_event_t *ev) {
  ucs_status_t rc = UCS_OK;
  void *recv_buf;
  size_t size;
  uint8_t am_id = UCT_PTL_HDR_GET_AM_ID(ev->match_bits);
  uint8_t prot_id = UCT_PTL_HDR_GET_PROT_ID(ev->match_bits);
  uct_ptl_recv_block_t *block;

  ucs_info("PORTALS: EQS EVENT '%s' idx=%d, "
           "sz=%lu, user=%p, start=%p, "
           "remote_offset=%lu",
           uct_ptl_event_str[ev->type], ev->pt_index, ev->mlength, ev->user_ptr,
           ev->start, ev->remote_offset);

  switch (ev->type) {
  case PTL_EVENT_PUT_OVERFLOW:
  case PTL_EVENT_PUT:
    if (prot_id == UCT_PTL_AM_SHORT) {
      recv_buf = ucs_alloca(iface->config.max_short);
      if (recv_buf == NULL) {
        ucs_error("PTL: could not alloca short buffer.");
        rc = UCS_ERR_NO_MEMORY;
      }
      uct_ptl_am_copy_short(ev->start, ev->mlength, ev->hdr_data, recv_buf);
      size = ev->mlength + sizeof(ev->hdr_data);
    } else {
      recv_buf = ev->start;
      size = ev->mlength;
    }

    /* First, invoke AM handler. */
    rc = uct_iface_invoke_am(&iface->super, am_id, recv_buf, size, 0);

    uct_ptl_iface_trace_am(ucs_derived_of(iface, uct_ptl_am_iface_t),
                           UCT_AM_TRACE_TYPE_RECV, am_id, recv_buf, size);
    break;
  case PTL_EVENT_AUTO_UNLINK:
    block = (uct_ptl_recv_block_t *)ev->user_ptr;
    rc = uct_ptl_recv_block_activate(block);
    break;

  case PTL_EVENT_LINK:
  case PTL_EVENT_GET_OVERFLOW:
  case PTL_EVENT_GET:
  case PTL_EVENT_AUTO_FREE:
  case PTL_EVENT_ACK:
  case PTL_EVENT_ATOMIC:
  case PTL_EVENT_FETCH_ATOMIC:
  case PTL_EVENT_SEARCH:
  case PTL_EVENT_SEND:
  case PTL_EVENT_REPLY:
  case PTL_EVENT_FETCH_ATOMIC_OVERFLOW:
  case PTL_EVENT_ATOMIC_OVERFLOW:
    ucs_error("PTL: event %s should not have been triggered",
              uct_ptl_event_str[ev->type]);
    rc = UCS_ERR_IO_ERROR;
    break;
  case PTL_EVENT_PT_DISABLED:
    ucs_error("PTL: control flow not implemented.");
    rc = UCS_ERR_IO_ERROR;
    break;
  default:
    break;
  }

  return rc;
}

ucs_status_t uct_ptl_am_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                    uct_completion_t *comp) {
  ucs_status_t rc;
  ptl_size_t last_seqn;
  uct_ptl_op_t *op = NULL;
  uct_ptl_am_iface_t *ptl_iface = ucs_derived_of(tl_iface, uct_ptl_am_iface_t);

  /* Load the sequence number of the last rma operations. */
  // TODO:  atomic load
  last_seqn = ptl_iface->rma_mmd->seqn - 1;

  rc = uct_ptl_md_progress(ptl_iface->rma_mmd);
  if (rc != UCS_OK)
    goto err;

  if (!ucs_queue_is_empty(&ptl_iface->rma_mmd->opq)) {
    rc = UCS_INPROGRESS;

    op = ucs_mpool_get(&ptl_iface->zcopy_mp);
    if (op == NULL) {
      ucs_error("PTL: could not allocate flush operation.");
      rc = UCS_ERR_NO_MEMORY;
      goto err;
    }
    op->comp = comp;
    op->seqn = last_seqn;

    // TODO: lock
    ucs_queue_push(&ptl_iface->rma_mmd->opq, &op->elem);
  }

err:
  return rc;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ptl_am_iface_t) {

  uct_base_iface_progress_disable(&self->super.super.super,
                                  UCT_PROGRESS_SEND | UCT_PROGRESS_RECV);

  ucs_mpool_cleanup(&self->bcopy_mp, 0);

  ucs_mpool_cleanup(&self->zcopy_mp, 0);

  uct_ptl_rq_fini(&self->rq);

  return;
}

static ucs_status_t uct_ptl_am_iface_get_addr(uct_iface_h tl_iface,
                                              uct_iface_addr_t *tl_addr) {
  uct_ptl_am_iface_addr_t *addr = (void *)tl_addr;
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_iface, uct_ptl_am_iface_t);
  uct_ptl_am_md_t *md = ucs_derived_of(iface->super.super.md, uct_ptl_am_md_t);

  addr->rma_pti = md->super.pti;
  addr->am_pti = iface->rq.pti;

  return UCS_OK;
}

static ucs_mpool_ops_t uct_ptl_am_mpool_ops = {
    .chunk_alloc = ucs_mpool_chunk_malloc,
    .chunk_release = ucs_mpool_chunk_free,
    .obj_init = NULL,
    .obj_cleanup = NULL,
    .obj_str = NULL,
};

static UCS_CLASS_INIT_FUNC(uct_ptl_am_iface_t, uct_md_h tl_md,
                           uct_worker_h worker,
                           const uct_iface_params_t *params,
                           const uct_iface_config_t *tl_config) {
  ucs_status_t rc = UCS_OK;
  uct_ptl_am_md_t *ptl_ms = ucs_derived_of(tl_md, uct_ptl_am_md_t);
  uct_ptl_am_iface_config_t *ptl_config =
      ucs_derived_of(tl_config, uct_ptl_am_iface_config_t);
  ucs_mpool_params_t mp_param;
  uct_ptl_mmd_param_t md_param;
  uct_ptl_rq_param_t rq_param;

  UCS_CLASS_CALL_SUPER_INIT(uct_ptl_iface_t, &uct_ptl_am_iface_tl_ops,
                            &uct_ptl_am_iface_ops, tl_md, worker, params,
                            &ptl_config->super);

  ucs_assert(sizeof(uint64_t) <= sizeof(ptl_hdr_data_t));

  /* Set configuration option. */
  self->super.config.max_short =
      ucs_min(uct_ptl_iface_md(&self->super)->limits.max_volatile_size,
              UCS_ALLOCA_MAX_SIZE);
  self->super.config.max_iovecs = 1;
  self->super.config.device_addr_size = sizeof(uct_ptl_device_addr_t);
  self->super.config.iface_addr_size = sizeof(uct_ptl_am_iface_addr_t);

  /* Set internal ptl operations */
  self->super.ops.handle_ev = uct_ptl_am_iface_handle_ev;

  /* Get MS MD for convenience. */
  self->rma_mmd = &ptl_ms->mmd;

  /* Pool of short message buffer. */
  mp_param = (ucs_mpool_params_t){
      .max_chunk_size = self->super.config.copyin_buf_per_block *
                        self->super.config.max_short,
      .elems_per_chunk = self->super.config.copyin_buf_per_block,
      .max_elems = self->super.config.max_copyin_buf,
      .elem_size = self->super.config.max_short,
      .alignment = 64,
      .align_offset = 0,
      .ops = &uct_ptl_am_mpool_ops,
      .name = "short-am-ops",
      .grow_factor = 1,
  };
  rc = ucs_mpool_init(&mp_param, &self->short_mp);
  if (rc != UCS_OK)
    goto err;

  /* Enable progression of RMA operation. */
  uct_ptl_iface_enable_progression(&self->super, &ptl_ms->mmd);

  /* Work pool of operation. */
  mp_param = (ucs_mpool_params_t){
      .max_chunk_size =
          self->super.config.max_outstanding_ops * sizeof(uct_ptl_op_t),
      .elems_per_chunk = self->super.config.max_outstanding_ops,
      .max_elems = self->super.config.max_outstanding_ops,
      .elem_size = sizeof(uct_ptl_op_t),
      .alignment = 64,
      .align_offset = 0,
      .ops = &uct_ptl_am_mpool_ops,
      .name = "rma-am-ops",
      .grow_factor = 1,
  };
  rc = ucs_mpool_init(&mp_param, &self->zcopy_mp);
  if (rc != UCS_OK)
    goto err;

  /* Initialize AM communication data structures. */
  /* Memory descriptor for local access and operation progression. */
  md_param = (uct_ptl_mmd_param_t){
      .flags = PTL_CT_ACK_REQ,
  };
  rc = uct_ptl_md_mdesc_init(&ptl_ms->super, &md_param, &self->am_mmd);
  if (rc != UCS_OK)
    goto err;

  // FIXME: add custom ptl function of progression enable
  uct_ptl_iface_enable_progression(&self->super, &self->am_mmd);

  /* Work pool of operation. */
  mp_param = (ucs_mpool_params_t){
      .max_chunk_size =
          self->super.config.copyin_buf_per_block *
          (sizeof(uct_ptl_op_t) + self->super.config.eager_block_size),
      .elems_per_chunk = self->super.config.copyin_buf_per_block,
      .max_elems = self->super.config.max_copyin_buf,
      .elem_size = sizeof(uct_ptl_op_t) + self->super.config.eager_block_size,
      .alignment = 64,
      .align_offset = 0,
      .ops = &uct_ptl_am_mpool_ops,
      .name = "bcopy-am-ops",
      .grow_factor = 1,
  };
  rc = ucs_mpool_init(&mp_param, &self->bcopy_mp);
  if (rc != UCS_OK)
    goto err;

  rq_param = (uct_ptl_rq_param_t){
      .items_per_chunk = self->super.config.num_eager_blocks,
      .min_items = 2,
      .max_items = 64 * self->super.config.num_eager_blocks,
      .item_size = self->super.config.eager_block_size,
      .options = ECR_PTL_BLOCK_AM,
      .min_free = self->super.config.eager_block_size,
  };

  rc = uct_ptl_rq_init(&self->super, &rq_param, &self->rq);
  if (rc != UCS_OK)
    goto err;

err:
  return rc;
}

static UCS_CLASS_DECLARE_DELETE_FUNC(uct_ptl_am_iface_t, uct_iface_t);

static uct_iface_ops_t uct_ptl_am_iface_tl_ops = {
    .ep_am_short = uct_ptl_am_ep_am_short,
    .ep_am_short_iov = uct_ptl_am_ep_am_short_iov,
    .ep_am_bcopy = uct_ptl_am_ep_am_bcopy,
    .ep_am_zcopy = uct_ptl_am_ep_am_zcopy,
    .ep_put_short = uct_ptl_am_ep_put_short,
    .ep_put_bcopy = uct_ptl_am_ep_put_bcopy,
    .ep_put_zcopy = uct_ptl_am_ep_put_zcopy,
    .ep_get_bcopy = uct_ptl_am_ep_get_bcopy,
    .ep_get_zcopy = uct_ptl_am_ep_get_zcopy,
    .ep_atomic_cswap64 = uct_ptl_am_ep_atomic_cswap64,
    .ep_atomic64_post = uct_ptl_am_ep_atomic64_post,
    .ep_atomic64_fetch = uct_ptl_am_ep_atomic64_fetch,
    .ep_atomic_cswap32 =
        (uct_ep_atomic_cswap32_func_t)ucs_empty_function_return_unsupported,
    .ep_atomic32_post =
        (uct_ep_atomic32_post_func_t)ucs_empty_function_return_unsupported,
    .ep_atomic32_fetch =
        (uct_ep_atomic32_fetch_func_t)ucs_empty_function_return_unsupported,
    .ep_pending_add = uct_ptl_am_ep_pending_add,
    .ep_pending_purge = uct_ptl_am_ep_pending_purge,
    .ep_flush = uct_ptl_am_ep_flush,
    .ep_fence = uct_ptl_am_ep_fence,
    .ep_check = uct_ptl_am_ep_check,
    .ep_create = UCS_CLASS_NEW_FUNC_NAME(uct_ptl_am_ep_t),
    .ep_destroy = UCS_CLASS_DELETE_FUNC_NAME(uct_ptl_am_ep_t),
    .ep_get_address = uct_ptl_am_ep_get_address,
    .ep_connect_to_ep = uct_base_ep_connect_to_ep,
    .iface_flush = uct_ptl_am_iface_flush,
    .iface_fence = uct_ptl_iface_fence,
    .iface_progress_enable = uct_base_iface_progress_enable,
    .iface_progress_disable = uct_base_iface_progress_disable,
    .iface_progress = uct_ptl_iface_progress,
    .iface_event_fd_get = ucs_empty_function_return_unsupported,
    .iface_event_arm = ucs_empty_function_return_unsupported,
    .iface_close = UCS_CLASS_DELETE_FUNC_NAME(uct_ptl_am_iface_t),
    .iface_query = uct_ptl_iface_query,
    .iface_get_address = uct_ptl_am_iface_get_addr,
    .iface_get_device_address = uct_ptl_iface_get_device_address,
    .iface_is_reachable = uct_base_iface_is_reachable,
};

static uct_ptl_iface_ops_t uct_ptl_am_iface_ops = {
    .super =
        {
            .iface_estimate_perf = ucs_empty_function_return_unsupported,
            .iface_vfs_refresh = (uct_iface_vfs_refresh_func_t)
                ucs_empty_function_return_unsupported,
            .ep_query =
                (uct_ep_query_func_t)ucs_empty_function_return_unsupported,
            .ep_invalidate =
                (uct_ep_invalidate_func_t)ucs_empty_function_return_unsupported,
            .ep_connect_to_ep_v2 = ucs_empty_function_return_unsupported,
            .iface_is_reachable_v2 = *(uct_iface_is_reachable_v2_func_t)
                                         ucs_empty_function_return_unsupported,
            .ep_is_connected = (uct_ep_is_connected_func_t)
                ucs_empty_function_return_unsupported,
        },
    .handle_ev = uct_ptl_am_iface_handle_ev,
};

UCS_CLASS_DEFINE(uct_ptl_am_iface_t, uct_ptl_iface_t);
static UCS_CLASS_DEFINE_NEW_FUNC(uct_ptl_am_iface_t, uct_iface_t, uct_md_h,
                                 uct_worker_h, const uct_iface_params_t *,
                                 const uct_iface_config_t *);
static UCS_CLASS_DEFINE_DELETE_FUNC(uct_ptl_am_iface_t, uct_iface_t);

UCT_TL_DEFINE_ENTRY(&uct_ptl_am_component, ptl_am,
                    uct_ptl_iface_query_tl_devices, uct_ptl_am_iface_t,
                    "PTL_AM_", uct_ptl_am_iface_config_table,
                    uct_ptl_am_iface_config_t);

UCT_SINGLE_TL_INIT(&uct_ptl_am_component, ptl_am, ctor, , )
