#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ptl_iface.h"
#include <ucs/sys/math.h>

#define UCT_PTL_IFACE_OVERHEAD 10e-8
#define UCT_PTL_IFACE_LATENCY  ucs_linear_func_make(80e-8, 0)

char *uct_ptl_event_str[] = {
        [PTL_EVENT_GET]                   = "PTL_EVENT_GET",
        [PTL_EVENT_GET_OVERFLOW]          = "PTL_EVENT_GET_OVERFLOW",
        [PTL_EVENT_PUT]                   = "PTL_EVENT_PUT",
        [PTL_EVENT_PUT_OVERFLOW]          = "PTL_EVENT_PUT_OVERFLOW",
        [PTL_EVENT_ATOMIC]                = "PTL_EVENT_ATOMIC",
        [PTL_EVENT_ATOMIC_OVERFLOW]       = "PTL_EVENT_ATOMIC_OVERFLOW",
        [PTL_EVENT_FETCH_ATOMIC]          = "PTL_EVENT_FETCH_ATOMIC",
        [PTL_EVENT_FETCH_ATOMIC_OVERFLOW] = "PTL_EVENT_FETCH_ATOMIC_OVERFLOW",
        [PTL_EVENT_REPLY]                 = "PTL_EVENT_REPLY",
        [PTL_EVENT_SEND]                  = "PTL_EVENT_SEND",
        [PTL_EVENT_ACK]                   = "PTL_EVENT_ACK",
        [PTL_EVENT_PT_DISABLED]           = "PTL_EVENT_PT_DISABLED",
        [PTL_EVENT_LINK]                  = "PTL_EVENT_LINK",
        [PTL_EVENT_AUTO_UNLINK]           = "PTL_EVENT_AUTO_UNLINK",
        [PTL_EVENT_AUTO_FREE]             = "PTL_EVENT_AUTO_FREE",
        [PTL_EVENT_SEARCH]                = "PTL_EVENT_SEARCH",
};
ucs_config_field_t uct_ptl_iface_config_table[] = {
        {"", "ALLOC=heap", NULL, ucs_offsetof(uct_ptl_iface_config_t, super),
         UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},

        {"MAX_OUTSTANDING_OPS", "512",
         "Maximum number of outstanding operations (default: 2048).",
         ucs_offsetof(uct_ptl_iface_config_t, max_outstanding_ops),
         UCS_CONFIG_TYPE_UINT},

        {"COPYIN_BUF_PER_BLOCK", "16",
         "Number of copyin buffers allocated per block (default: 2)",
         ucs_offsetof(uct_ptl_iface_config_t, copyin_buf_per_block),
         UCS_CONFIG_TYPE_UINT},

        {"COPYOUT_BUF_PER_BLOCK", "16",
         "Number of copyout buffers allocated per block (default: 2)",
         ucs_offsetof(uct_ptl_iface_config_t, copyout_buf_per_block),
         UCS_CONFIG_TYPE_UINT},

        {"MIN_COPYIN_BUF", "2",
         "Minimum number of copyin buffers per working queues (default: 2)",
         ucs_offsetof(uct_ptl_iface_config_t, min_copyin_buf),
         UCS_CONFIG_TYPE_UINT},

        {"MAX_COPYIN_BUF", "512",
         "Maximum number of copyin buffers per working queues (default: 8)",
         ucs_offsetof(uct_ptl_iface_config_t, max_copyin_buf),
         UCS_CONFIG_TYPE_UINT},

        {"MAX_COPYOUT_BUF", "512",
         "Maximum number of copyout buffers per working queues (default: 8)",
         ucs_offsetof(uct_ptl_iface_config_t, max_copyout_buf),
         UCS_CONFIG_TYPE_UINT},

        {"NUM_EAGER_BLOCKS", "32",
         "Number of eager blocks for receiving unexpected messages (default: "
         "32).",
         ucs_offsetof(uct_ptl_iface_config_t, num_eager_blocks),
         UCS_CONFIG_TYPE_UINT},

        {"EAGER_BLOCK_SIZE", "8192",
         "Size of a single eager block (default: 8192).",
         ucs_offsetof(uct_ptl_iface_config_t, eager_block_size),
         UCS_CONFIG_TYPE_UINT},

        {"MAX_EP_RETRIES", "16",
         "Maximum nunber of send retry on a given endpoint (default: 16).",
         ucs_offsetof(uct_ptl_iface_config_t, max_ep_retries),
         UCS_CONFIG_TYPE_UINT},

        {NULL},
};

ucs_status_t
uct_ptl_iface_query_tl_devices(uct_md_h                   md,
                               uct_tl_device_resource_t **tl_devices_p,
                               unsigned                  *num_tl_devices_p)
{
  uct_ptl_md_t *ptl_md = ucs_derived_of(md, uct_ptl_md_t);
  return uct_single_device_resource(md, ptl_md->device, UCT_DEVICE_TYPE_NET,
                                    UCS_SYS_DEVICE_ID_UNKNOWN, tl_devices_p,
                                    num_tl_devices_p);
}

int uct_ptl_iface_is_reachable_v2(const uct_iface_h tl_iface,
                                  const uct_iface_is_reachable_params_t *params)
{

  if (!uct_iface_is_reachable_params_valid(
              params, UCT_IFACE_IS_REACHABLE_FIELD_DEVICE_ADDR)) {
    return 0;
  }

  return uct_iface_scope_is_reachable(tl_iface, params);
}

ucs_status_t uct_ptl_iface_query(uct_iface_h iface, uct_iface_attr_t *attr)
{
  uct_ptl_iface_t *ptl_if = ucs_derived_of(iface, uct_ptl_iface_t);

  uct_base_iface_query(&ptl_if->super, attr);

  attr->cap.am.max_short = ptl_if->config.max_short - sizeof(uint64_t);
  attr->cap.am.max_bcopy = ptl_if->config.eager_block_size;
  attr->cap.am.max_zcopy = 0;
  attr->cap.am.max_iov   = ptl_if->config.max_iovecs;

  attr->cap.tag.recv.min_recv   = 0;
  attr->cap.tag.eager.max_short = ptl_if->config.max_short;
  attr->cap.tag.eager.max_bcopy = ptl_if->config.eager_block_size;
  attr->cap.tag.eager.max_zcopy = ptl_if->config.max_msg_size;
  attr->cap.tag.eager.max_iov   = ptl_if->config.max_iovecs;
  attr->cap.tag.rndv.max_hdr    = 128;
  attr->cap.tag.rndv.max_iov    = 1;
  attr->cap.tag.rndv.max_zcopy  = ptl_if->config.max_msg_size;

  attr->cap.put.max_short       = ptl_if->config.max_short;
  attr->cap.put.max_bcopy       = ptl_if->config.eager_block_size;
  attr->cap.put.min_zcopy       = 0;
  attr->cap.put.max_zcopy       = ptl_if->config.max_msg_size;
  attr->cap.put.max_iov         = ptl_if->config.max_iovecs;
  attr->cap.put.opt_zcopy_align = 1;
  attr->cap.put.align_mtu       = attr->cap.put.opt_zcopy_align;

  attr->cap.get.max_short       = ptl_if->config.max_short;
  attr->cap.get.max_bcopy       = ptl_if->config.eager_block_size;
  attr->cap.get.min_zcopy       = 0;
  attr->cap.get.max_zcopy       = ptl_if->config.max_msg_size;
  attr->cap.get.max_iov         = ptl_if->config.max_iovecs;
  attr->cap.get.opt_zcopy_align = 1;
  attr->cap.get.align_mtu       = attr->cap.get.opt_zcopy_align;

  attr->ep_addr_len     = ptl_if->config.ep_addr_size;
  attr->iface_addr_len  = ptl_if->config.iface_addr_size;
  attr->device_addr_len = ptl_if->config.device_addr_size;

  attr->cap.flags = UCT_IFACE_FLAG_AM_BCOPY | UCT_IFACE_FLAG_PUT_BCOPY |
                    UCT_IFACE_FLAG_GET_BCOPY | UCT_IFACE_FLAG_PUT_SHORT |
                    UCT_IFACE_FLAG_PUT_ZCOPY | UCT_IFACE_FLAG_GET_ZCOPY |
                    UCT_IFACE_FLAG_PENDING | UCT_IFACE_FLAG_CB_SYNC |
                    UCT_IFACE_FLAG_INTER_NODE |
                    UCT_IFACE_FLAG_CONNECT_TO_IFACE | UCT_IFACE_FLAG_EP_CHECK;

  attr->cap.atomic32.op_flags |=
          UCS_BIT(UCT_ATOMIC_OP_ADD) | UCS_BIT(UCT_ATOMIC_OP_AND) |
          UCS_BIT(UCT_ATOMIC_OP_XOR) | UCS_BIT(UCT_ATOMIC_OP_OR) |
          UCS_BIT(UCT_ATOMIC_OP_CSWAP);
  attr->cap.atomic32.fop_flags |=
          UCS_BIT(UCT_ATOMIC_OP_ADD) | UCS_BIT(UCT_ATOMIC_OP_AND) |
          UCS_BIT(UCT_ATOMIC_OP_XOR) | UCS_BIT(UCT_ATOMIC_OP_OR) |
          UCS_BIT(UCT_ATOMIC_OP_CSWAP);
  attr->cap.atomic64.op_flags |=
          UCS_BIT(UCT_ATOMIC_OP_ADD) | UCS_BIT(UCT_ATOMIC_OP_AND) |
          UCS_BIT(UCT_ATOMIC_OP_XOR) | UCS_BIT(UCT_ATOMIC_OP_OR) |
          UCS_BIT(UCT_ATOMIC_OP_CSWAP);
  attr->cap.atomic64.fop_flags |=
          UCS_BIT(UCT_ATOMIC_OP_ADD) | UCS_BIT(UCT_ATOMIC_OP_AND) |
          UCS_BIT(UCT_ATOMIC_OP_XOR) | UCS_BIT(UCT_ATOMIC_OP_OR) |
          UCS_BIT(UCT_ATOMIC_OP_CSWAP);
  attr->cap.flags |= UCT_IFACE_FLAG_ATOMIC_CPU;

  attr->latency             = UCT_PTL_IFACE_LATENCY;
  attr->bandwidth.dedicated = 8192 * UCS_MBYTE;
  attr->bandwidth.shared    = 0;
  attr->overhead            = UCT_PTL_IFACE_OVERHEAD;
  attr->priority            = 1;

  return UCS_OK;
}

ucs_status_t uct_ptl_iface_get_device_address(uct_iface_h        tl_iface,
                                              uct_device_addr_t *tl_addr)
{
  uct_ptl_device_addr_t *addr  = (void *)tl_addr;
  uct_ptl_iface_t       *iface = ucs_derived_of(tl_iface, uct_ptl_iface_t);

  addr->pid = uct_ptl_iface_md(iface)->pid;

  return UCS_OK;
}

int uct_ptl_md_progress(uct_ptl_mmd_t *mmd)
{
  ucs_status_t     rc = UCS_OK;
  ucs_queue_iter_t iter;
  uct_ptl_op_t    *op;
  int              progressed = 0;

  if (ucs_queue_is_empty(&mmd->opq)) {
    return progressed;
  }

  rc = uct_ptl_wrap(PtlCTGet(mmd->cth, &mmd->p_cnt));
  if (rc != UCS_OK) {
    progressed = rc;
    goto err;
  }

  if (mmd->p_cnt.failure > 0) {
    progressed = UCT_ERR_PTL_CT_FAILURE;
    goto err;
  }

  ucs_queue_for_each_safe (op, iter, &mmd->opq, elem) {
    if (UCS_CIRCULAR_COMPARE64(mmd->p_cnt.success, >, op->seqn)) {
      ucs_queue_del_iter(&mmd->opq, iter);
      progressed++;

      switch (op->type) {
      case UCT_PTL_OP_RMA_GET_BCOPY:
        op->get_bcopy.unpack(op->get_bcopy.arg, op->buffer, op->size);
        break;
      case UCT_PTL_OP_RMA_GET_ZCOPY_TAG:
        op->tag.ctx->tag_consumed_cb(op->tag.ctx);
        op->tag.ctx->completed_cb(op->tag.ctx, op->tag.tag, 0, op->size, NULL,
                                  UCS_OK);
        goto err;
        break;
      default:
        break;
      }

      if (op->comp != NULL) {
        uct_invoke_completion(op->comp, UCS_OK);
      }
      if (op->buffer != NULL) {
        ucs_mpool_put(op->buffer);
      }
      ucs_debug("PTL: op complete. id=%lu, type=%d", op->seqn, op->type);
      ucs_mpool_put(op);
    }
  }

err:
  return progressed;
}

// FIXME: make use of UCT_PROGRESS_{SEND,RECV} flags.
unsigned uct_ptl_iface_progress(uct_iface_t *super)
{
  ucs_status_t     rc;
  int              ret;
  int              progressed = 0, tmp;
  ptl_event_t      ev;
  uct_ptl_mmd_t   *mmd;
  uct_ptl_iface_t *iface = ucs_derived_of(super, uct_ptl_iface_t);
  uct_ptl_md_t    *md    = ucs_derived_of(iface->super.md, uct_ptl_md_t);
  uct_pending_req_priv_queue_t *priv;

handle_error:
  while (1) {
    ret = PtlEQGet(md->eqh, &ev);

    switch (ret) {
    case PTL_OK:
      rc = iface->ops.handle_ev(iface, &ev);
      if (rc != UCS_OK)
        goto err;
      progressed++;
      break;
    case PTL_EQ_EMPTY:
      goto out;
      break;
    case PTL_EQ_DROPPED:
      ucs_error("PTL: EQ event dropped.");
      goto err;
      break;
    default:
      uct_ptl_rc_log(ret);
      rc = UCS_ERR_IO_ERROR;
      goto err;
    }
  }

out:
  ucs_list_for_each (mmd, &iface->mds, elem) {
    tmp = uct_ptl_md_progress(mmd);
    if (tmp == UCT_ERR_PTL_CT_FAILURE) {
      goto handle_error;
    } else if (tmp < 0) {
      progressed = tmp;
      goto err;
    }
    progressed += tmp;
  }

  uct_pending_queue_dispatch(priv, &iface->pending_q, 1);

  // TODO: rework.
  iface->ops.cancel_ops(iface);

err:
  return progressed;
}

static ucs_mpool_ops_t uct_ptl_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = NULL,
        .obj_cleanup   = NULL,
        .obj_str       = NULL,
};

UCS_CLASS_INIT_FUNC(uct_ptl_iface_t, uct_iface_ops_t *tl_ops,
                    uct_ptl_iface_ops_t *ops, uct_md_h tl_md,
                    uct_worker_h worker, const uct_iface_params_t *params,
                    const uct_ptl_iface_config_t *config)
{
  ucs_status_t       rc     = UCS_OK;
  uct_ptl_md_t      *ptl_md = ucs_derived_of(tl_md, uct_ptl_md_t);
  ucs_mpool_params_t mp_param;

  UCS_CLASS_CALL_SUPER_INIT(
          uct_base_iface_t, tl_ops, &ops->super, tl_md, worker, params,
          &config->super UCS_STATS_ARG(
                  ((params->field_mask & UCT_IFACE_PARAM_FIELD_STATS_ROOT) &&
                   (params->stats_root != NULL)) ?
                          params->stats_root :
                          dev->stats)
                   UCS_STATS_ARG(params->mode.device.dev_name));

  self->config.copyin_buf_per_block  = config->copyin_buf_per_block;
  self->config.min_copyin_buf        = config->min_copyin_buf;
  self->config.max_copyin_buf        = config->max_copyin_buf;
  self->config.eager_block_size      = config->eager_block_size;
  self->config.num_eager_blocks      = config->num_eager_blocks;
  self->config.max_events            = config->max_events;
  self->config.max_outstanding_ops   = config->max_outstanding_ops;
  self->config.max_copyout_buf       = config->max_copyout_buf;
  self->config.copyout_buf_per_block = config->copyout_buf_per_block;

  self->config.max_iovecs   = ptl_md->limits.max_iovecs;
  self->config.max_msg_size = ptl_md->limits.max_msg_size;
  self->config.max_short    = ptl_md->limits.max_waw_ordered_size;

  ucs_list_head_init(&self->mds);
  ucs_queue_head_init(&self->pending_q);

  /* Work pool of operation. */
  mp_param = (ucs_mpool_params_t){
          .max_chunk_size =
                  self->config.max_outstanding_ops * sizeof(uct_ptl_op_t),
          .elems_per_chunk = self->config.max_outstanding_ops,
          .max_elems       = self->config.max_outstanding_ops,
          .elem_size       = sizeof(uct_ptl_op_t),
          .alignment       = 64,
          .align_offset    = 0,
          .ops             = &uct_ptl_mpool_ops,
          .name            = "ptl-ops",
          .grow_factor     = 1,
  };
  rc = ucs_mpool_init(&mp_param, &self->ops_mp);

  /* Work pool of operation. */
  mp_param = (ucs_mpool_params_t){
          .max_chunk_size =
                  self->config.max_outstanding_ops * sizeof(uct_ptl_op_t),
          .elems_per_chunk = self->config.max_outstanding_ops,
          .max_elems       = self->config.max_outstanding_ops,
          .elem_size       = sizeof(uct_ptl_op_t),
          .alignment       = 64,
          .align_offset    = 0,
          .ops             = &uct_ptl_mpool_ops,
          .name            = "ptl-flush-ops",
          .grow_factor     = 1,
  };
  rc = ucs_mpool_init(&mp_param, &self->flush_ops_mp);

err:
  return rc;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ptl_iface_t)
{
  ucs_mpool_cleanup(&self->ops_mp, 1);
  ucs_mpool_cleanup(&self->copyin_mp, 1);
  return;
}

UCS_CLASS_DEFINE(uct_ptl_iface_t, uct_base_iface_t);
