#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ptl_iface.h"

char *uct_ptl_event_str[] = {
    [PTL_EVENT_GET] = "PTL_EVENT_GET",
    [PTL_EVENT_GET_OVERFLOW] = "PTL_EVENT_GET_OVERFLOW",
    [PTL_EVENT_PUT] = "PTL_EVENT_PUT",
    [PTL_EVENT_PUT_OVERFLOW] = "PTL_EVENT_PUT_OVERFLOW",
    [PTL_EVENT_ATOMIC] = "PTL_EVENT_ATOMIC",
    [PTL_EVENT_ATOMIC_OVERFLOW] = "PTL_EVENT_ATOMIC_OVERFLOW",
    [PTL_EVENT_FETCH_ATOMIC] = "PTL_EVENT_FETCH_ATOMIC",
    [PTL_EVENT_FETCH_ATOMIC_OVERFLOW] = "PTL_EVENT_FETCH_ATOMIC_OVERFLOW",
    [PTL_EVENT_REPLY] = "PTL_EVENT_REPLY",
    [PTL_EVENT_SEND] = "PTL_EVENT_SEND",
    [PTL_EVENT_ACK] = "PTL_EVENT_ACK",
    [PTL_EVENT_PT_DISABLED] = "PTL_EVENT_PT_DISABLED",
    [PTL_EVENT_LINK] = "PTL_EVENT_LINK",
    [PTL_EVENT_AUTO_UNLINK] = "PTL_EVENT_AUTO_UNLINK",
    [PTL_EVENT_AUTO_FREE] = "PTL_EVENT_AUTO_FREE",
    [PTL_EVENT_SEARCH] = "PTL_EVENT_SEARCH",
};
ucs_config_field_t uct_ptl_iface_config_table[] = {
    {"", "ALLOC=heap", NULL, ucs_offsetof(uct_ptl_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},

    {"MAX_EVENTS", "2048",
     "Maximum number of events per event queue (default: 2048).",
     ucs_offsetof(uct_ptl_iface_config_t, max_events), UCS_CONFIG_TYPE_UINT},

    {"MAX_OUTSTANDING_OPS", "2048",
     "Maximum number of outstanding operations (default: 2048).",
     ucs_offsetof(uct_ptl_iface_config_t, max_outstanding_ops),
     UCS_CONFIG_TYPE_UINT},

    {"COPYIN_BUF_PER_BLOCK", "8",
     "Number of copyin buffers allocated per block (default: 2)",
     ucs_offsetof(uct_ptl_iface_config_t, copyin_buf_per_block),
     UCS_CONFIG_TYPE_UINT},

    {"MIN_COPYIN_BUF", "2",
     "Minimum number of copyin buffers per working queues (default: 2)",
     ucs_offsetof(uct_ptl_iface_config_t, min_copyin_buf),
     UCS_CONFIG_TYPE_UINT},

    {"MAX_COPYIN_BUF", "8",
     "Maximum number of copyin buffers per working queues (default: 8)",
     ucs_offsetof(uct_ptl_iface_config_t, max_copyin_buf),
     UCS_CONFIG_TYPE_UINT},

    {"NUM_EAGER_BLOCKS", "8",
     "Number of eager blocks for receiving unexpected messages (default: 32).",
     ucs_offsetof(uct_ptl_iface_config_t, num_eager_blocks),
     UCS_CONFIG_TYPE_UINT},

    {"EAGER_BLOCK_SIZE", "8192",
     "Size of a single eager block (default: 8192).",
     ucs_offsetof(uct_ptl_iface_config_t, eager_block_size),
     UCS_CONFIG_TYPE_UINT},

    {NULL},
};

ucs_status_t
uct_ptl_iface_query_tl_devices(uct_md_h md,
                               uct_tl_device_resource_t **tl_devices_p,
                               unsigned *num_tl_devices_p) {
  uct_ptl_md_t *ptl_md = ucs_derived_of(md, uct_ptl_md_t);
  return uct_single_device_resource(md, ptl_md->device, UCT_DEVICE_TYPE_NET,
                                    UCS_SYS_DEVICE_ID_UNKNOWN, tl_devices_p,
                                    num_tl_devices_p);
}

ucs_status_t uct_ptl_iface_query(uct_iface_h iface, uct_iface_attr_t *attr) {
  uct_ptl_iface_t *ptl_if = ucs_derived_of(iface, uct_ptl_iface_t);

  attr->cap.am.max_short = ptl_if->config.max_short - sizeof(uint64_t);
  attr->cap.am.max_bcopy = ptl_if->config.eager_block_size;
  attr->cap.am.max_zcopy = ptl_if->config.max_msg_size;
  attr->cap.am.max_iov = ptl_if->config.max_iovecs;

  attr->cap.tag.recv.min_recv = 0;
  attr->cap.tag.eager.max_short = ptl_if->config.max_short;
  attr->cap.tag.eager.max_bcopy = ptl_if->config.eager_block_size;
  attr->cap.tag.eager.max_zcopy = ptl_if->config.max_msg_size;
  attr->cap.tag.eager.max_iov = ptl_if->config.max_iovecs;

  attr->cap.put.max_short = ptl_if->config.max_short;
  attr->cap.put.max_bcopy = ptl_if->config.eager_block_size;
  attr->cap.put.max_zcopy = ptl_if->config.max_msg_size;
  attr->cap.put.max_iov = ptl_if->config.max_iovecs;

  attr->cap.get.max_short = ptl_if->config.max_short;
  attr->cap.get.max_bcopy = ptl_if->config.eager_block_size;
  attr->cap.get.max_zcopy = ptl_if->config.max_msg_size;
  attr->cap.get.max_iov = ptl_if->config.max_iovecs;

  attr->ep_addr_len = ptl_if->config.ep_addr_size;
  attr->iface_addr_len = ptl_if->config.iface_addr_size;
  attr->device_addr_len = ptl_if->config.device_addr_size;

  attr->cap.flags = UCT_IFACE_FLAG_AM_BCOPY | UCT_IFACE_FLAG_PUT_BCOPY |
                    UCT_IFACE_FLAG_GET_BCOPY | UCT_IFACE_FLAG_PUT_SHORT |
                    UCT_IFACE_FLAG_PUT_ZCOPY | UCT_IFACE_FLAG_GET_ZCOPY |
                    UCT_IFACE_FLAG_PENDING | UCT_IFACE_FLAG_CB_SYNC |
                    UCT_IFACE_FLAG_INTER_NODE | UCT_IFACE_FLAG_CONNECT_TO_IFACE;

  attr->cap.atomic32.op_flags |=
      UCS_BIT(UCT_ATOMIC_OP_ADD) | UCS_BIT(UCT_ATOMIC_OP_AND) |
      UCS_BIT(UCT_ATOMIC_OP_XOR) | UCS_BIT(UCT_ATOMIC_OP_OR);
  // attr->cap.atomic32.fop_flags |=
  //     UCS_BIT(UCT_ATOMIC_OP_ADD) | UCS_BIT(UCT_ATOMIC_OP_AND) |
  //     UCS_BIT(UCT_ATOMIC_OP_XOR) | UCS_BIT(UCT_ATOMIC_OP_OR);
  attr->cap.atomic64.op_flags |=
      UCS_BIT(UCT_ATOMIC_OP_ADD) | UCS_BIT(UCT_ATOMIC_OP_AND) |
      UCS_BIT(UCT_ATOMIC_OP_XOR) | UCS_BIT(UCT_ATOMIC_OP_OR);
  // attr->cap.atomic64.fop_flags |=
  //     UCS_BIT(UCT_ATOMIC_OP_ADD) | UCS_BIT(UCT_ATOMIC_OP_AND) |
  //     UCS_BIT(UCT_ATOMIC_OP_XOR) | UCS_BIT(UCT_ATOMIC_OP_OR);
  attr->cap.flags |= UCT_IFACE_FLAG_ATOMIC_CPU;

  attr->cap.event_flags =
      UCT_IFACE_FLAG_EVENT_SEND_COMP | UCT_IFACE_FLAG_EVENT_RECV;

  return UCS_OK;
}

ucs_status_t uct_ptl_iface_get_device_address(uct_iface_h tl_iface,
                                              uct_device_addr_t *tl_addr) {
  uct_ptl_device_addr_t *addr = (void *)tl_addr;
  uct_ptl_iface_t *iface = ucs_derived_of(tl_iface, uct_ptl_iface_t);

  addr->pid = uct_ptl_iface_md(iface)->pid;

  return UCS_OK;
}

#define seqn_gt(a, b) ((int64_t)((a) - (b)) > 0)
ucs_status_t uct_ptl_md_progress(uct_ptl_mmd_t *mmd) {
  ucs_status_t rc = UCS_OK;
  ucs_queue_iter_t iter;
  uct_ptl_op_t *op;

  if (ucs_queue_is_empty(&mmd->opq)) {
    return rc;
  }

  rc = uct_ptl_wrap(PtlCTGet(mmd->cth, &mmd->p_cnt));
  if (rc != UCS_OK) {
    goto err;
  }

  if (mmd->p_cnt.failure > 0) {
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  ucs_queue_for_each_safe(op, iter, &mmd->opq, elem) {
    if (seqn_gt(mmd->p_cnt.success, op->seqn)) {
      ucs_queue_del_iter(&mmd->opq, iter);

      switch (op->type) {
      case UCT_PTL_OP_RMA_GET_BCOPY:
        op->get_bcopy.unpack(op->get_bcopy.arg, op + 1, op->size);
        break;
      case UCT_PTL_OP_ATOMIC_POST:
        ucs_debug("PTL: atomic add op complete. op=%p, seqn=%lu", op, op->seqn);
        break;
      default:
        break;
      }

      if (op->comp != NULL) {
        uct_invoke_completion(op->comp, UCS_OK);
      }
      ucs_mpool_put(op);
    }
  }

err:
  return rc;
}

// FIXME: make use of UCT_PROGRESS_{SEND,RECV} flags.
unsigned uct_ptl_iface_progress(uct_iface_t *super) {
  ucs_status_t rc;
  int ret;
  ptl_event_t ev;
  uct_ptl_mmd_t *mmd;
  uct_ptl_iface_t *iface = ucs_derived_of(super, uct_ptl_iface_t);

  ucs_list_for_each(mmd, &iface->mds, elem) {
    rc = uct_ptl_md_progress(mmd);
    if (rc != UCS_OK)
      goto out;
  }

  while (1) {
    ret = PtlEQGet(iface->eqh, &ev);

    switch (ret) {
    case PTL_OK:
      rc = iface->ops.handle_ev(iface, &ev);
      if (rc != UCS_OK)
        goto out;
      break;
    case PTL_EQ_EMPTY:
      goto out;
      break;
    case PTL_EQ_DROPPED:
      goto out;
      break;
    default:
      uct_ptl_rc_log(ret);
      rc = UCS_ERR_IO_ERROR;
      goto out;
    }
  }

out:
  return rc;
}

ucs_status_t uct_ptl_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                 uct_completion_t *comp) {
  return UCS_ERR_UNSUPPORTED;
}

ucs_status_t uct_ptl_iface_fence(uct_iface_h tl_iface, unsigned flags) {
  return UCS_ERR_UNSUPPORTED;
}

UCS_CLASS_INIT_FUNC(uct_ptl_iface_t, uct_iface_ops_t *tl_ops,
                    uct_ptl_iface_ops_t *ops, uct_md_h tl_md,
                    uct_worker_h worker, const uct_iface_params_t *params,
                    const uct_ptl_iface_config_t *config) {
  ucs_status_t rc = UCS_OK;
  uct_ptl_md_t *ptl_md = ucs_derived_of(tl_md, uct_ptl_md_t);

  UCS_CLASS_CALL_SUPER_INIT(
      uct_base_iface_t, tl_ops, &ops->super, tl_md, worker, params,
      &config->super UCS_STATS_ARG(
          ((params->field_mask & UCT_IFACE_PARAM_FIELD_STATS_ROOT) &&
           (params->stats_root != NULL))
              ? params->stats_root
              : dev->stats) UCS_STATS_ARG(params->mode.device.dev_name));

  self->config.copyin_buf_per_block = config->copyin_buf_per_block;
  self->config.min_copyin_buf = config->min_copyin_buf;
  self->config.max_copyin_buf = config->max_copyin_buf;
  self->config.eager_block_size = config->eager_block_size;
  self->config.num_eager_blocks = config->num_eager_blocks;
  self->config.max_events = config->max_events;
  self->config.max_outstanding_ops = config->max_outstanding_ops;

  self->config.max_iovecs = ptl_md->limits.max_iovecs;
  self->config.max_msg_size = ptl_md->limits.max_msg_size;
  self->config.max_short = ptl_md->limits.max_waw_ordered_size;

  rc = uct_ptl_wrap(
      PtlEQAlloc(ptl_md->nih, self->config.max_events, &self->eqh));

  ucs_list_head_init(&self->mds);

  return rc;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ptl_iface_t) {
  uct_ptl_wrap(PtlEQFree(self->eqh));

  return;
}

UCS_CLASS_DEFINE(uct_ptl_iface_t, uct_base_iface_t);
