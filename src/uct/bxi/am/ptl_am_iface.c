#include "ptl_am_iface.h"
#include "ptl_am_ep.h"
#include "ptl_am_md.h"

static uct_iface_ops_t uct_ptl_am_iface_tl_ops;
static uct_ptl_iface_ops_t uct_ptl_am_iface_ops;

ucs_config_field_t uct_ptl_am_iface_config_table[] = {
    {"", "", NULL, ucs_offsetof(uct_ptl_am_iface_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_ptl_iface_config_table)},

    {"TM_ENABLE", "n", "Enable HW tag matching",
     ucs_offsetof(uct_ptl_am_iface_config_t, tm.enable), UCS_CONFIG_TYPE_BOOL},

    {"TM_LIST_SIZE", "32",
     "Limits the number of tags posted to the HW for matching. The actual "
     "limit \n"
     "is a minimum between this value and the maximum value supported by the "
     "HW. \n"
     "-1 means no limit.",
     ucs_offsetof(uct_ptl_am_iface_config_t, tm.list_size),
     UCS_CONFIG_TYPE_UINT},

    {NULL}};

static void uct_ptl_am_handle_failure(uct_ptl_iface_t *ptl_iface,
                                      uct_ptl_op_t *op, ptl_ni_fail_t fail) {
  ucs_status_t status;
  ptl_ct_event_t fail_dec = {.success = 1, .failure = -1};
  uct_ptl_am_iface_t *iface = ucs_derived_of(ptl_iface, uct_ptl_am_iface_t);
  uct_ptl_am_ep_t *ep = ucs_derived_of(op->ep, uct_ptl_am_ep_t);

  ucs_assert(ep != NULL);
  // TODO: add support for retry if error.
  ep->super.conn_state = UCT_PTL_EP_CONN_CLOSED;

  status = uct_ptl_wrap(PtlCTInc(op->mmd->cth, fail_dec));

  if (op->buffer != NULL) {
    ucs_mpool_put_inline(op->buffer);
  }
  ucs_mpool_put_inline(op);

  status =
      uct_iface_handle_ep_err(&iface->super.super.super, &ep->super.super.super,
                              UCS_ERR_ENDPOINT_TIMEOUT);

  ucs_assert(status == UCS_OK);
}

static ucs_status_t uct_ptl_am_iface_cancel_ops(uct_ptl_iface_t *tl_iface) {
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_iface, uct_ptl_am_iface_t);
  uct_ptl_op_t *op;
  ucs_queue_iter_t iter;

  ucs_queue_for_each_safe(op, iter, &iface->tm.canceled_ops, elem) {
    if (op->tag.cancel) {
      op->tag.ctx->completed_cb(op->tag.ctx, op->tag.tag, 0, op->size, NULL,
                                UCS_ERR_CANCELED);
    }
    uct_ptl_am_iface_tag_del_from_hash(iface, op->tag.buffer);
    ucs_queue_del_iter(&iface->tm.canceled_ops, iter);
  }

  return UCS_OK;
}

static ucs_status_t uct_ptl_am_iface_handle_tag_ev(uct_ptl_iface_t *super,
                                                   ptl_event_t *ev) {
  ucs_status_t rc = UCS_OK;
  uct_ptl_am_iface_t *iface = ucs_derived_of(super, uct_ptl_am_iface_t);
  uct_ptl_op_t *op = (uct_ptl_op_t *)ev->user_ptr;
  int is_rndv =
      UCT_PTL_HDR_GET_PROT_ID(ev->hdr_data) == UCT_PTL_RNDV_MAGIC ? 1 : 0;
  uct_ptl_recv_block_t *block;
  uct_tag_context_t *tag_ctx;
  uct_ptl_am_hdr_rndv_t *hdr;

  assert(op);

  ucs_debug("PTL: event. type=%s", uct_ptl_event_str[ev->type]);

  // TODO: check for truncated messages
  switch (ev->type) {
  case PTL_EVENT_ACK:
    if (ev->ni_fail_type != PTL_NI_OK) {
      ucs_debug("PTL: handle failure. op=%p, seqn=%lu", op, op->seqn);
      uct_ptl_am_handle_failure(&iface->super, op, ev->ni_fail_type);
    }
    break;
  case PTL_EVENT_AUTO_UNLINK:
  case PTL_EVENT_PUT_OVERFLOW:
    op->tag.flags |= UCT_PTL_OP_FLAG_OVERFLOW;
    iface->tm.num_tags++;
    break;
  case PTL_EVENT_PUT:
    if (op->type == UCT_PTL_OP_BLOCK) {
      if (is_rndv) {
        hdr = ev->start;
        rc =
            iface->tm.rndv_unexp.cb(iface->tm.rndv_unexp.arg, 0, ev->match_bits,
                                    (const void *)(hdr + 1),
                                    ev->mlength - sizeof(uct_ptl_am_hdr_rndv_t),
                                    hdr->remote_addr, hdr->length, NULL);
      } else {
        rc = iface->tm.eager_unexp.cb(iface->tm.eager_unexp.arg, ev->start,
                                      ev->mlength, UCT_CB_PARAM_FLAG_FIRST,
                                      ev->match_bits, ev->hdr_data, NULL);
      }
      block = ucs_container_of(op, uct_ptl_recv_block_t, op);
      uct_ptl_recv_block_activate(block);
    } else {
      tag_ctx = op->tag.ctx;
      if (is_rndv) {
        hdr = ev->start;
        tag_ctx->tag_consumed_cb(tag_ctx);
        tag_ctx->rndv_cb(tag_ctx, ev->match_bits, hdr + 1, hdr->length, UCS_OK,
                         0);
      } else {
        tag_ctx->tag_consumed_cb(tag_ctx);
        tag_ctx->completed_cb(tag_ctx, ev->match_bits, ev->hdr_data,
                              ev->mlength, NULL, UCS_OK);
        uct_ptl_am_iface_tag_del_from_hash(iface, op->tag.buffer);
      }
      iface->tm.num_tags++;
    }
    break;
  case PTL_EVENT_REPLY:
  case PTL_EVENT_GET_OVERFLOW:
  case PTL_EVENT_AUTO_FREE:
  case PTL_EVENT_ATOMIC:
  case PTL_EVENT_FETCH_ATOMIC:
  case PTL_EVENT_FETCH_ATOMIC_OVERFLOW:
  case PTL_EVENT_ATOMIC_OVERFLOW:
  case PTL_EVENT_PT_DISABLED:
  case PTL_EVENT_LINK:
  case PTL_EVENT_SEARCH:
  case PTL_EVENT_SEND:
    ucs_error("PTL: event %s should not have been triggered",
              uct_ptl_event_str[ev->type]);
    rc = UCS_ERR_IO_ERROR;
    break;
  default:
    break;
  }

  return rc;
}

static ucs_status_t uct_ptl_am_iface_handle_ev(uct_ptl_iface_t *iface,
                                               ptl_event_t *ev) {
  ucs_status_t rc = UCS_OK;
  uint8_t am_id = UCT_PTL_HDR_GET_AM_ID(ev->match_bits);
  uct_ptl_op_t *op = (uct_ptl_op_t *)ev->user_ptr;
  uct_ptl_recv_block_t *block;

  switch (ev->type) {
  case PTL_EVENT_ACK:
    if (ev->ni_fail_type != PTL_NI_OK) {
      ucs_debug("PTL: handle failure. op=%p, seqn=%lu", op, op->seqn);
      uct_ptl_am_handle_failure(iface, op, ev->ni_fail_type);
    }
    break;
  case PTL_EVENT_PUT_OVERFLOW:
  case PTL_EVENT_PUT:
    rc = uct_iface_invoke_am(&iface->super, am_id, ev->start, ev->mlength, 0);

    uct_ptl_iface_trace_am(ucs_derived_of(iface, uct_ptl_am_iface_t),
                           UCT_AM_TRACE_TYPE_RECV, am_id, ev->start,
                           ev->mlength);
    break;
  case PTL_EVENT_AUTO_UNLINK:
    block = ucs_container_of(op, uct_ptl_recv_block_t, op);
    rc = uct_ptl_recv_block_activate(block);
    break;
  case PTL_EVENT_LINK:
  case PTL_EVENT_GET_OVERFLOW:
  case PTL_EVENT_GET:
  case PTL_EVENT_AUTO_FREE:
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
    ucs_error("PTL: event %s. Control flow not implemented.",
              uct_ptl_event_str[ev->type]);
    rc = UCS_OK;
    break;
  default:
    break;
  }

  return rc;
}

static ucs_status_t uct_ptl_am_iface_handle_event(uct_ptl_iface_t *tl_iface,
                                                  ptl_event_t *ev) {
  ucs_status_t rc = UCS_OK;
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_iface, uct_ptl_am_iface_t);

  if (ev->pt_index == iface->am_rq.pti) {
    rc = uct_ptl_am_iface_handle_ev(tl_iface, ev);
  } else if (ev->pt_index == iface->tag_rq.pti) {
    rc = uct_ptl_am_iface_handle_tag_ev(tl_iface, ev);
  } else {
    rc = UCS_ERR_IO_ERROR;
  }
  return rc;
}

ucs_status_t uct_ptl_am_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                    uct_completion_t *comp) {
  ucs_status_t status = UCS_OK;
  ptl_size_t last_seqn = 0;
  uct_ptl_op_t *op = NULL;
  uct_ptl_mmd_t *mmd, *last_mmd = NULL;
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_iface, uct_ptl_am_iface_t);

  ucs_list_for_each(mmd, &iface->super.mds, elem) {
    if (ucs_queue_is_empty(&mmd->opq)) {
      continue;
    }

    /* Load the sequence number of the last operations. */
    if (last_seqn < mmd->seqn) {
      last_seqn = mmd->seqn;
      last_mmd = mmd;
    }

    status = UCS_INPROGRESS;
  }

  if (status == UCS_INPROGRESS && comp != NULL) {
    op = ucs_mpool_get(&iface->super.flush_ops_mp);
    if (ucs_unlikely(op == NULL)) {
      ucs_error("Failed to allocate flush completion");
      return UCS_ERR_NO_MEMORY;
    }
    op->type = UCT_PTL_OP_RMA_FLUSH;
    op->comp = comp;
    op->buffer = NULL;
    // FIXME: uniformize pending and outstanding operation count
    op->seqn = last_seqn - 1 + ucs_queue_length(&iface->super.pending_q);

    ucs_queue_push(&last_mmd->opq, &op->elem);
  }

err:
  return status;
}

ucs_status_t uct_ptl_am_iface_fence(uct_iface_h tl_iface, unsigned flags) {
  ucs_status_t rc;
  unsigned progressed;

  do {
    progressed = uct_ptl_iface_progress(tl_iface);
    if (progressed < 0) {
      rc = progressed;
      goto err;
    }
  } while ((rc = uct_ptl_am_iface_flush(tl_iface, flags, NULL)) ==
           UCS_INPROGRESS);

err:
  return rc;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ptl_am_iface_t) {
  void *recv_buffer;
  uct_base_iface_progress_disable(&self->super.super.super,
                                  UCT_PROGRESS_SEND | UCT_PROGRESS_RECV);

  kh_foreach_key(&self->tm.tag_addrs, recv_buffer, {
    ucs_debug("destroying iface %p, with recv buffer %p offloaded to the HW",
              self, recv_buffer);
  });
  kh_destroy_inplace(uct_ptl_am_tag_addrs, &self->tm.tag_addrs);

  uct_ptl_rq_fini(&self->am_rq);
  uct_ptl_rq_fini(&self->tag_rq);

  return;
}

static ucs_status_t uct_ptl_am_iface_query(uct_iface_h tl_iface,
                                           uct_iface_attr_t *attr) {
  ucs_status_t rc;
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_iface, uct_ptl_am_iface_t);

  rc = uct_ptl_iface_query(tl_iface, attr);
  if (rc != UCS_OK) {
    goto err;
  }

  if (!UCT_PTL_IFACE_TM_IS_ENABLED(iface)) {
    return rc;
  }

  attr->cap.flags |= UCT_IFACE_FLAG_TAG_EAGER_BCOPY;

  attr->cap.tag.rndv.max_zcopy = iface->super.config.max_msg_size;

  /* TMH can carry 2 additional bytes of private data */
  attr->cap.tag.rndv.max_hdr = sizeof(ptl_hdr_data_t);
  attr->cap.tag.rndv.max_iov = 1;
  attr->cap.tag.recv.max_zcopy = iface->super.config.max_msg_size;
  attr->cap.tag.recv.max_iov = 1;
  attr->cap.tag.recv.min_recv = 0;
  attr->cap.tag.recv.max_outstanding = iface->tm.num_tags;
  attr->cap.tag.eager.max_iov = 1;
  attr->cap.tag.eager.max_bcopy =
      iface->super.config.eager_block_size - sizeof(uint64_t);
  attr->cap.tag.eager.max_zcopy = iface->super.config.max_msg_size;

err:
  return rc;
}

static ucs_status_t uct_ptl_am_iface_get_addr(uct_iface_h tl_iface,
                                              uct_iface_addr_t *tl_addr) {
  uct_ptl_am_iface_addr_t *addr = (void *)tl_addr;
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_iface, uct_ptl_am_iface_t);
  uct_ptl_am_md_t *md = ucs_derived_of(iface->super.super.md, uct_ptl_am_md_t);

  addr->rma_pti = md->super.pti;
  addr->am_pti = iface->am_rq.pti;
  addr->tag_pti = iface->tag_rq.pti;

  return UCS_OK;
}

static ucs_mpool_ops_t uct_ptl_am_mpool_ops = {
    .chunk_alloc = ucs_mpool_chunk_malloc,
    .chunk_release = ucs_mpool_chunk_free,
    .obj_init = NULL,
    .obj_cleanup = NULL,
    .obj_str = NULL,
};

static ucs_status_t
uct_ptl_am_iface_tag_init(uct_ptl_am_iface_t *iface,
                          const uct_iface_params_t *params,
                          const uct_ptl_am_iface_config_t *tl_config) {
  iface->tm.eager_unexp.cb = params->eager_cb;
  iface->tm.rndv_unexp.cb = params->rndv_cb;
  iface->tm.eager_unexp.arg =
      UCT_IFACE_PARAM_VALUE(params, eager_arg, HW_TM_EAGER_ARG, NULL);
  iface->tm.rndv_unexp.arg =
      UCT_IFACE_PARAM_VALUE(params, eager_arg, HW_TM_RNDV_ARG, NULL);
  iface->tm.unexpected_cnt = 0;
  iface->tm.num_outstanding = 0;
  iface->tm.num_tags = tl_config->tm.list_size;

  kh_init_inplace(uct_ptl_am_tag_addrs, &iface->tm.tag_addrs);
  ucs_queue_head_init(&iface->tm.canceled_ops);

  return UCS_OK;
}

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
  self->super.config.ep_addr_size = sizeof(uct_ptl_am_ep_addr_t);
  self->tm.num_tags = ptl_config->tm.list_size;
  self->tm.enabled = ptl_config->tm.enable;

  uct_ptl_am_iface_tag_init(self, params, ptl_config);

  /* Set internal ptl operations */
  self->super.ops.handle_ev = uct_ptl_am_iface_handle_event;
  self->super.ops.cancel_ops = uct_ptl_am_iface_cancel_ops;

  /* Get MS MD for convenience. */
  self->rma_mmd = &ptl_ms->mmd;

  /* Enable progression of RMA operation. */
  uct_ptl_iface_enable_progression(&self->super, &ptl_ms->mmd);

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
      .max_chunk_size = self->super.config.copyin_buf_per_block *
                        self->super.config.eager_block_size,
      .elems_per_chunk = self->super.config.copyin_buf_per_block,
      .max_elems = self->super.config.max_copyin_buf,
      .elem_size = self->super.config.eager_block_size,
      .alignment = 64,
      .align_offset = 0,
      .ops = &uct_ptl_am_mpool_ops,
      .name = "copyin-mp",
      .grow_factor = 1,
  };
  rc = ucs_mpool_init(&mp_param, &self->super.copyin_mp);
  if (rc != UCS_OK)
    goto err;

  rq_param = (uct_ptl_rq_param_t){
      .items_per_chunk = self->super.config.copyout_buf_per_block,
      .min_items = 2,
      .max_items = self->super.config.max_copyout_buf,
      .item_size = self->super.config.eager_block_size *
                   self->super.config.num_eager_blocks,
      .options = ECR_PTL_BLOCK_AM,
      .min_free = self->super.config.eager_block_size,
      .name = "am-rq-blocks",
  };

  rc = uct_ptl_rq_init(&self->super, &rq_param, &self->am_rq);
  if (rc != UCS_OK)
    goto err;

  rq_param = (uct_ptl_rq_param_t){
      .items_per_chunk = self->super.config.copyout_buf_per_block,
      .min_items = 2,
      .max_items = self->super.config.max_copyout_buf,
      .item_size = self->super.config.eager_block_size *
                   self->super.config.num_eager_blocks,
      .options = ECR_PTL_BLOCK_TAG,
      .min_free = self->super.config.eager_block_size,
      .name = "tag-rq-blocks",
  };

  rc = uct_ptl_rq_init(&self->super, &rq_param, &self->tag_rq);
  if (rc != UCS_OK)
    goto err;

  ucs_debug("PTL: iface addr. iface=%p, nid=%d, pid=%d, am pti=%d, rma pti=%d, "
            "tag pti=%d",
            self, ptl_ms->super.pid.phys.nid, ptl_ms->super.pid.phys.pid,
            self->am_rq.pti, ptl_ms->super.pti, self->tag_rq.pti);
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
    .ep_tag_rndv_zcopy = uct_ptl_am_ep_tag_rndv_zcopy,
    .ep_tag_eager_zcopy = uct_ptl_am_ep_tag_eager_zcopy,
    .ep_tag_eager_bcopy = uct_ptl_am_ep_tag_eager_bcopy,
    .ep_tag_eager_short = ucs_empty_function_return_unsupported,
    .ep_tag_rndv_cancel = uct_ptl_am_ep_tag_rndv_cancel,
    .ep_tag_rndv_request = uct_ptl_am_ep_tag_rndv_request,
    .ep_atomic_cswap64 = uct_ptl_am_ep_atomic_cswap64,
    .ep_atomic64_post = uct_ptl_am_ep_atomic64_post,
    .ep_atomic64_fetch = uct_ptl_am_ep_atomic64_fetch,
    .ep_atomic_cswap32 = uct_ptl_am_ep_atomic_cswap32,
    .ep_atomic32_post = uct_ptl_am_ep_atomic32_post,
    .ep_atomic32_fetch = uct_ptl_am_ep_atomic32_fetch,
    .ep_pending_add = uct_ptl_ep_pending_add,
    .ep_pending_purge = uct_ptl_ep_pending_purge,
    .ep_flush = uct_ptl_am_ep_flush,
    .ep_fence = uct_ptl_am_ep_fence,
    .ep_check = uct_ptl_am_ep_check,
    .ep_create = UCS_CLASS_NEW_FUNC_NAME(uct_ptl_am_ep_t),
    .ep_destroy = UCS_CLASS_DELETE_FUNC_NAME(uct_ptl_am_ep_t),
    .ep_get_address = uct_ptl_am_ep_get_address,
    .ep_connect_to_ep = uct_base_ep_connect_to_ep,
    .iface_flush = uct_ptl_am_iface_flush,
    .iface_fence = uct_ptl_am_iface_fence,
    .iface_progress_enable = uct_base_iface_progress_enable,
    .iface_progress_disable = uct_base_iface_progress_disable,
    .iface_progress = uct_ptl_iface_progress,
    .iface_event_fd_get = ucs_empty_function_return_unsupported,
    .iface_event_arm = ucs_empty_function_return_success,
    .iface_close = UCS_CLASS_DELETE_FUNC_NAME(uct_ptl_am_iface_t),
    .iface_query = uct_ptl_am_iface_query,
    .iface_get_address = uct_ptl_am_iface_get_addr,
    .iface_get_device_address = uct_ptl_iface_get_device_address,
    .iface_is_reachable = uct_base_iface_is_reachable,
    .iface_tag_recv_zcopy = uct_ptl_am_iface_tag_recv_zcopy,
    .iface_tag_recv_cancel = uct_ptl_am_iface_tag_recv_cancel,
};

static uct_ptl_iface_ops_t uct_ptl_am_iface_ops = {
    .super =
        {
            .iface_estimate_perf = uct_base_iface_estimate_perf,
            .iface_vfs_refresh = (uct_iface_vfs_refresh_func_t)
                ucs_empty_function_return_unsupported,
            .ep_query =
                (uct_ep_query_func_t)ucs_empty_function_return_unsupported,
            .ep_invalidate =
                (uct_ep_invalidate_func_t)ucs_empty_function_return_unsupported,
            .ep_connect_to_ep_v2 = ucs_empty_function_return_unsupported,
            .iface_is_reachable_v2 = *(uct_iface_is_reachable_v2_func_t)
                                         ucs_empty_function_return_unsupported,
            .ep_is_connected = uct_ptl_am_ep_is_connected,
        },
    .handle_ev = uct_ptl_am_iface_handle_ev,
    .handle_failure = uct_ptl_am_handle_failure,
    .cancel_ops = uct_ptl_am_iface_cancel_ops,
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

UCT_SINGLE_TL_INIT(&uct_ptl_am_component, ptl_am, ctor, PtlInit(), PtlFini())
