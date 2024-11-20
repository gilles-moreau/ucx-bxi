#include "ptl_am_iface.h"
#include "ptl_am_ep.h"
#include "ptl_am_md.h"

ucs_config_field_t uct_ptl_am_iface_config_table[] = {
    {"", "", NULL, ucs_offsetof(uct_ptl_am_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_ptl_iface_config_table)},

    {NULL}};

static ucs_status_t uct_ptl_am_iface_handle_ev(uct_ptl_iface_t *iface,
                                               ptl_event_t *ev) {
  ucs_status_t rc = UCS_OK;
  uint8_t am_id;
  uct_ptl_recv_block_t *block;

  ucs_info("PORTALS: EQS EVENT '%s' eqh=%lu, idx=%d, "
           "sz=%lu, user=%p, start=%p, "
           "remote_offset=%lu, iface=%lu",
           uct_ptl_event_str[ev->type], (uint64_t)iface->eqh, ev->pt_index,
           ev->mlength, ev->user_ptr, ev->start, ev->remote_offset,
           (uint64_t)0);

  switch (ev->type) {
  case PTL_EVENT_PUT_OVERFLOW:
  case PTL_EVENT_PUT:
    /* First, invoke AM handle. */
    am_id = UCT_PTL_HDR_GET_AM_ID(ev->hdr_data);
    rc = uct_iface_invoke_am(&iface->super, am_id, ev->start, ev->mlength, 0);
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

static ucs_status_t uct_ptl_am_flush_iface(uct_iface_h iface,
                                           uct_completion_t *comp,
                                           unsigned flags) {
  ucs_status_t rc;
  ptl_size_t last_seqn;
  uct_ptl_op_t *op = NULL;
  uct_ptl_am_iface_t *ptl_iface = ucs_derived_of(iface, uct_ptl_am_iface_t);

  /* Load the sequence number of the last rma operations. */
  // TODO:  atomic load
  last_seqn = ptl_iface->rma_md->seqn - 1;

  rc = uct_ptl_md_progress(ptl_iface->rma_md);
  if (rc != UCS_OK)
    goto err;

  if (!ucs_queue_is_empty(&ptl_iface->rma_md->opq)) {
    rc = UCS_INPROGRESS;

    op = ucs_mpool_get(&ptl_iface->rma_mp);
    if (op == NULL) {
      ucs_error("PTL: could not allocate flush operation.");
      rc = UCS_ERR_NO_MEMORY;
      goto err;
    }
    op->comp = comp;
    op->seqn = last_seqn;

    // TODO: lock
    ucs_queue_push(&ptl_iface->rma_md->opq, &op->elem);
  }

err:
  return rc;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ptl_am_iface_t) {
  uct_ptl_am_md_t *ptl_md =
      ucs_derived_of(&self->super.super.md, uct_ptl_am_md_t);

  uct_ptl_md_mdesc_fini(&self->am_md);

  uct_ptl_md_me_fini(&ptl_md->super, &ptl_md->me);

  ucs_mpool_cleanup(&self->am_mp, 0);

  ucs_mpool_cleanup(&self->rma_mp, 0);

  uct_ptl_rq_fini(&self->rq);

  return;
}

static void uct_ptl_am_iface_get_addr(uct_iface_h iface,
                                      uct_iface_addr_t *addr) {
  uct_ptl_am_iface_addr_t *ptl_addr = (uct_ptl_am_iface_addr_t *)addr;
  uct_ptl_am_iface_t *ptl_iface = ucs_derived_of(iface, uct_ptl_am_iface_t);
  uct_ptl_am_md_t *ptl_ms =
      ucs_derived_of(ptl_iface->super.super.md, uct_ptl_am_md_t);

  ptl_addr->super.pid = ptl_ms->super.pid;
  ptl_addr->rma_pti = ptl_ms->me.idx;
  ptl_addr->am_pti = ptl_iface->rq.pti;

  return;
}

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
    .ep_pending_add = uct_rc_ep_pending_add,
    .ep_pending_purge = uct_rc_ep_pending_purge,
    .ep_flush = uct_ptl_am_ep_flush,
    .ep_fence = uct_ptl_am_ep_fence,
    .ep_check = uct_rc_ep_check,
    .ep_create = UCS_CLASS_NEW_FUNC_NAME(uct_ptl_am_ep_t),
    .ep_destroy = UCS_CLASS_DELETE_FUNC_NAME(uct_ptl_am_ep_t),
    .ep_get_address = uct_ptl_am_ep_get_address,
    .ep_connect_to_ep = uct_base_ep_connect_to_ep,
    .iface_flush = uct_rc_iface_flush,
    .iface_fence = uct_rc_iface_fence,
    .iface_progress_enable = uct_ptl_am_iface_common_progress_enable,
    .iface_progress_disable = uct_base_iface_progress_disable,
    .iface_progress = uct_rc_iface_do_progress,
    .iface_event_fd_get = uct_ib_iface_event_fd_get,
    .iface_event_arm = uct_rc_iface_event_arm,
    .iface_close = UCS_CLASS_DELETE_FUNC_NAME(uct_ptl_am_iface_t),
    .iface_query = uct_ptl_am_iface_query,
    .iface_get_address = ucs_empty_function_return_success,
    .iface_get_device_address = uct_ib_iface_get_device_address,
    .iface_is_reachable = uct_base_iface_is_reachable,
};

static uct_ptl_iface_ops_t uct_ptl_am_iface_ops = {
    .super =
        {
            .iface_estimate_perf = ucs_empty_function_return_unsupported,
            .iface_vfs_refresh = ucs_empty_function_return_unsupported,
            .ep_query =
                (uct_ep_query_func_t)ucs_empty_function_return_unsupported,
            .ep_invalidate =
                (uct_ep_invalidate_func_t)ucs_empty_function_return_unsupported,
            .ep_connect_to_ep_v2 = ucs_empty_function_return_unsupported,
            .iface_is_reachable_v2 = ucs_empty_function_return_unsupported,
            .ep_is_connected = ucs_empty_function_return_unsupported,
        },
    .handle_ev = uct_ptl_am_iface_handle_ev,
};

static UCS_CLASS_INIT_FUNC(uct_ptl_am_iface_t, uct_md_h tl_md,
                           uct_worker_h worker,
                           const uct_iface_params_t *params,
                           const uct_iface_config_t *tl_config) {
  ucs_status_t rc = UCS_OK;
  uct_ptl_am_md_t *ptl_ms = ucs_derived_of(tl_md, uct_ptl_am_md_t);
  ucs_mpool_params_t mp_ops_param;
  uct_ptl_mmd_param_t md_param;
  uct_ptl_rq_param_t rq_param;

UCS_CLASS_CALL_SUPER_INIT(uct_ptl_iface_t, &uct_ptl_am_iface_tl_ops, tl_md, ,
  rc = ECC_CLASS_CALL_SUPER_INIT(uct_ptl_iface_t, self, ms, device,
                                 &config->super);
  if (rc != UCS_OK) {
    goto err;
  }

  /* Set capabilities. */
  self->super.super.cap = ECR_IFACE_CAP_RMA | ECR_IFACE_CAP_AM;

  /* Get MS MD for convenience. */
  self->rma_md = &ptl_ms->md;

  /* Enable progression of RMA operation. */
  uct_ptl_iface_enable_progression(&self->super, &ptl_ms->md);

  /* Work pool of operation. */
  mp_ops_param = (ucs_mpool_param_t){
      .elem_per_chunk = self->super.config.max_outstanding_ops,
      .min_elems = 0,
      .max_elems = self->super.config.max_outstanding_ops,
      .elem_size = sizeof(uct_ptl_op_t),
      .alignment = 64,
      .free_func = free,
      .malloc_func = malloc,
  };
  rc = ucs_mpool_init(&self->rma_mp, &mp_ops_param);
  if (rc != UCS_OK)
    goto err;

  /* Initialize AM communication data structures. */
  /* Memory descriptor for local access and operation progression. */
  md_param = (uct_ptl_md_param_t){
      .flags = PTL_CT_ACK_REQ,
  };
  rc = uct_ptl_ms_md_init(&ptl_ms->super, &md_param, &self->am_md);
  if (rc != UCS_OK)
    goto err;

  uct_ptl_iface_enable_progression(&self->super, &self->am_md);

  /* Work pool of operation. */
  mp_ops_param = (ucs_mpool_param_t){
      .elem_per_chunk = self->super.config.copyin_buf_per_block,
      .min_elems = self->super.config.min_copyin_buf,
      .max_elems = self->super.config.max_copyin_buf,
      .elem_size = sizeof(uct_ptl_op_t) + self->super.config.eager_block_size,
      .alignment = 64,
      .free_func = free,
      .malloc_func = malloc,
  };
  rc = ucs_mpool_init(&self->am_mp, &mp_ops_param);
  if (rc != UCS_OK)
    goto err;

  rq_param = (uct_ptl_rq_param_t){
      .items_per_chunk = self->super.config.num_eager_blocks,
      .min_items = 2,
      .max_items = self->super.config.num_eager_blocks,
      .item_size = self->super.config.eager_block_size,
      .options = ECR_PTL_BLOCK_AM,
      .min_free = self->super.config.eager_block_size,
  };

  rc = uct_ptl_rq_init(&self->super, &rq_param, &self->rq);
  if (rc != UCS_OK)
    goto err;

  self->super.super.iface_addr_size = sizeof(uct_ptl_am_iface_addr_t);
  self->super.super.packed_rkey_size = 0;

err:
  return rc;
}

ECC_CLASS_DEFINE_CLEAN_FUNC(uct_ptl_am_iface_t) {
  ucs_status_t rc;
  uct_ptl_am_ms_t *ptl_am_ms =
      ucs_derived_of(self->super.super.ms, uct_ptl_am_ms_t);

  rc = uct_ptl_ms_md_fini(&self->am_md);
  if (rc != UCS_OK)
    goto err;

  rc = uct_ptl_ms_me_fini(&ptl_am_ms->super, &ptl_am_ms->me);
  if (rc != UCS_OK)
    goto err;

  ucs_mpool_fini(&self->am_mp);

  ucs_mpool_fini(&self->rma_mp);

  rc = uct_ptl_rq_fini(&self->rq);
  if (rc != UCS_OK) {
    ucs_error("PTL: could not release am receive queue.");
    goto err;
  }

  ECC_CLASS_CALL_SUPER_CLEAN(uct_ptl_iface_t, self);
err:
  return;
}

UCS_CLASS_DEFINE(uct_ptl_am_iface_t, uct_ptl_iface_t);
static UCS_CLASS_DEFINE_NEW_FUNC(uct_ptl_am_iface_t, uct_iface_t, uct_md_h,
                                 uct_worker_h, const uct_iface_params_t *,
                                 const uct_iface_config_t *);
static UCS_CLASS_DEFINE_DELETE_FUNC(uct_ptl_am_iface_t, uct_iface_t);

ucs_status_t uct_ptl_am_iface_open(uct_ms_h ms, uct_iface_config_t *config,
                                   uct_iface_h *iface_p) {
  ucs_status_t rc = UCS_OK;
  uct_ptl_iface_t *ptl_iface;
  uct_ptl_am_iface_config_t *ptl_config =
      ucs_derived_of(config, uct_ptl_am_iface_config_t);

  rc = ECC_CLASS_NEW(uct_ptl_am_iface_t, &ptl_iface, ms, ms->dev, ptl_config);
  if (rc != UCS_OK)
    goto err;

  ptl_iface->ops.handle_ev = uct_ptl_am_iface_handle_ev;

  ptl_iface->super.ops.send_am_bcopy = uct_ptl_send_am_bcopy;
  ptl_iface->super.ops.send_am_zcopy = uct_ptl_send_am_zcopy;
  ptl_iface->super.ops.put_zcopy = uct_ptl_am_put_zcopy;
  ptl_iface->super.ops.get_zcopy = uct_ptl_am_get_zcopy;
  ptl_iface->super.ops.flush_iface = uct_ptl_am_flush_iface;
  ptl_iface->super.ops.iface_progress = uct_ptl_iface_progress;
  ptl_iface->super.ops.iface_close = uct_ptl_iface_am_close;
  ptl_iface->super.ops.iface_get_addr = uct_ptl_am_iface_get_addr;
  ptl_iface->super.ops.iface_get_attr = uct_ptl_iface_get_attr;
  ptl_iface->super.ops.ep_create = uct_ptl_create_am_ep;
  ptl_iface->super.ops.ep_delete = uct_ptl_delete_am_ep;

  *iface_p = (uct_iface_t *)ptl_iface;
err:
  return rc;
}

uct_rail_t ptl_am_rail = {
    .name = "ptl_am",
    .iface_config =
        {
            .cf = &uct_ptl_am_iface_config_tab,
            .cf_size = sizeof(uct_ptl_am_iface_config_t),
        },
    .iface_open = uct_ptl_am_iface_open,
    .flags = 0,
};
ECR_RAIL_REGISTER(&ptl_am_component, &ptl_am_rail);
ECC_CONFIG_REGISTER(uct_ptl_am_iface_config_tab);
