#include "ptl_am_ep.h"
#include "ptl_am_iface.h"

ucs_status_t uct_ptl_am_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t hdr,
                                    const void *buffer, unsigned length) {
  ucs_status_t rc;
  uct_ptl_am_ep_t *ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_ptl_am_iface_t);

  ucs_assert(length <= iface->super.config.max_short);
  rc = uct_ptl_wrap(PtlPut(ep->am_md->mdh, (ptl_size_t)buffer, length,
                           PTL_CT_ACK_REQ, ep->super.pid, ep->am_pti, id, 0,
                           NULL, hdr));

  return rc;
}

ucs_status_t uct_ptl_am_ep_am_short_iov(uct_ep_h ep, uint8_t id,
                                        const uct_iov_t *iov, size_t iovcnt) {
  return UCS_ERR_UNSUPPORTED;
}

ssize_t uct_ptl_am_ep_am_bcopy(uct_ep_h ep, uint8_t id,
                               uct_pack_callback_t pack, void *arg,
                               unsigned flags) {
  ucs_status_t rc = UCS_OK;
  ptl_match_bits_t hdr = 0;
  uct_ptl_am_ep_t *ptl_ep = ucs_derived_of(ep, uct_ptl_am_ep_t);

  void *start = NULL;
  ssize_t size = 0;
  uct_ptl_op_t *op = ucs_mpool_get(ptl_ep->am_mp);

  if (op == NULL) {
    ucs_warn("PTL: reached max outstanding operations.");
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }
  op->comp = NULL;
  op->seqn = ptl_ep->am_md->seqn++;

  start = (void *)(op + 1);
  if (start == NULL) {
    ucs_error("PTL: could not allocate bcopy buffer.");
    size = UCS_ERR_NO_RESOURCE;
    goto err;
  }
  size = pack(start, arg);
  if (size < 0) {
    goto err;
  }

  rc = uct_ptl_wrap(PtlPut(ptl_ep->am_md->mdh, (ptl_size_t)start, size,
                           PTL_CT_ACK_REQ, ptl_ep->super.pid, ptl_ep->am_pti,
                           UCT_PTL_HDR_SET(hdr, id), 0, NULL, 0));

  if (rc != UCS_OK) {
    ucs_mpool_put(op);
    size = UCS_ERR_IO_ERROR;
    goto err;
  }

  ucs_queue_push(&ptl_ep->am_md->opq, &op->elem);

err:
  return size;
}

ucs_status_t uct_ptl_am_ep_am_zcopy(uct_ep_h tl_ep, uint8_t id,
                                    const void *header, unsigned header_length,
                                    const uct_iov_t *iov, size_t iovcnt,
                                    unsigned flags, uct_completion_t *comp) {
  return UCS_ERR_UNSUPPORTED;
#if 0 
    int                 i;
    ucs_status_t        rc       = UCS_OK;
    uct_ptl_am_ep_t    *ptl_ep   = ucs_derived_of(ep, uct_ptl_am_ep_t);
    uct_ptl_am_iface_t *am_iface = ucs_derived_of(&ptl_ep->super.super.iface,
                                                  uct_ptl_am_iface_t);
    ptl_md_t            iov_md;


    uct_ptl_op_t *op = uct_ptl_wq_get_item(am_iface->buf_wq);
    if (op == NULL) {
        ucs_error("PTL: could not allocate operation.");
        rc = ECC_ERR_NORESOURCES;
        goto err;
    }

    op->iov.iov = malloc((iovcnt + 1) * sizeof(ptl_iovec_t));
    if (op->iov.iov == NULL) {
        ucs_error("PTL: could not allocate ptl iov.");
        rc = ECC_ERR_OUT_OF_MEMORY;
        goto err;
    }

    assert(iovcnt + 1 <= (size_t)am_iface->super.super.config.max_iovec);

    /* Fill up IOV structure and compute total size. */
    op->iov.iov[0].iov_len  = header_length;
    op->iov.iov[0].iov_base = (void *)header;

    for (i = 0; i < (int)iovcnt; i++) {
        op->iov.iov[1 + i].iov_base = iov[i].iov_base;
    }

    iov_md = (ptl_md_t){
            .start     = op->iov.iov,
            .length    = iovcnt + 1,
            .ct_handle = am_iface->rma_cq->cth,
            .eq_handle = PTL_EQ_NONE,
            .options   = PTL_MD_EVENT_SEND_DISABLE | PTL_IOVEC,
    };

    /* Set Memory Descriptor handle. */
    rc = uct_ptl_wrap(PtlMDBind(am_iface->super.nih, &iov_md, NULL));
    if (rc != UCS_OK) {
        goto err;
    }

err:
    return rc;
#endif
}

ucs_status_t uct_ptl_am_ep_put_short(uct_ep_h tl_ep, const void *buffer,
                                     unsigned length, uint64_t remote_addr,
                                     uct_rkey_t rkey) {
  return UCS_ERR_UNSUPPORTED;
}

ssize_t uct_ptl_am_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                                void *arg, uint64_t remote_addr,
                                uct_rkey_t rkey) {
  return UCS_ERR_UNSUPPORTED;
}

ucs_status_t uct_ptl_am_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                     size_t iovcnt, uint64_t remote_addr,
                                     uct_rkey_t rkey, uct_completion_t *comp) {
  ucs_status_t rc = UCS_OK;
  uct_ptl_am_ep_t *ptl_ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_op_t *op = ucs_mpool_get(ptl_ep->rma_mp);

  ucs_assert(iovcnt == 1);

  if (op == NULL) {
    ucs_warn("PTL: reached max outstanding operations.");
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op->comp = comp;
  op->size = iov[0].length;
  op->seqn = ptl_ep->rma_md->seqn++;

  rc = uct_ptl_wrap(PtlPut(ptl_ep->rma_md->mdh, (ptl_size_t)iov[0].buffer,
                           op->size, PTL_CT_ACK_REQ, ptl_ep->super.pid,
                           ptl_ep->rma_pti, 0, remote_addr, NULL, 0));

  if (rc != UCS_OK) {
    ucs_mpool_put(op);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  ucs_queue_push(&ptl_ep->rma_md->opq, &op->elem);

err:
  return rc;
}

ucs_status_t uct_ptl_am_ep_get_bcopy(uct_ep_h tl_ep,
                                     uct_unpack_callback_t unpack_cb, void *arg,
                                     size_t length, uint64_t remote_addr,
                                     uct_rkey_t rkey, uct_completion_t *comp) {
  return UCS_ERR_UNSUPPORTED;
}

ucs_status_t uct_ptl_am_ep_get_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                     size_t iovcnt, uint64_t remote_addr,
                                     uct_rkey_t rkey, uct_completion_t *comp) {
  ucs_status_t rc = UCS_OK;
  uct_ptl_am_ep_t *ptl_ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_op_t *op = ucs_mpool_get(ptl_ep->rma_mp);

  if (op == NULL) {
    ucs_warn("PTL: reached max outstanding operations.");
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op->comp = comp;
  op->size = iov[0].length;
  op->seqn = ptl_ep->rma_md->seqn++;

  rc = uct_ptl_wrap(PtlGet(ptl_ep->rma_md->mdh, (ptl_size_t)iov[0].buffer,
                           op->size, ptl_ep->super.pid, ptl_ep->rma_pti, 0,
                           remote_addr, NULL));

  if (rc != UCS_OK) {
    ucs_mpool_put(op);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  ucs_queue_push(&ptl_ep->rma_md->opq, &op->elem);

err:
  return rc;
}

ucs_status_t uct_ptl_am_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare,
                                          uint64_t swap, uint64_t remote_addr,
                                          uct_rkey_t rkey, uint64_t *result,
                                          uct_completion_t *comp) {
  return UCS_ERR_UNSUPPORTED;
}

ucs_status_t uct_ptl_am_ep_atomic64_post(uct_ep_h tl_ep, unsigned opcode,
                                         uint64_t value, uint64_t remote_addr,
                                         uct_rkey_t rkey) {
  return UCS_ERR_UNSUPPORTED;
}

ucs_status_t uct_ptl_am_ep_atomic64_fetch(uct_ep_h tl_ep,
                                          uct_atomic_op_t opcode,
                                          uint64_t value, uint64_t *result,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp) {
  return UCS_ERR_UNSUPPORTED;
}

ucs_status_t uct_ptl_am_ep_flush(uct_ep_h tl_ep, unsigned flags,
                                 uct_completion_t *comp) {
  return UCS_ERR_UNSUPPORTED;
}

ucs_status_t uct_ptl_am_ep_fence(uct_ep_h tl_ep, unsigned flags) {
  return UCS_ERR_UNSUPPORTED;
}

void uct_ptl_am_ep_post_check(uct_ep_h tl_ep) { return; }

ucs_status_t uct_ptl_am_ep_get_address(uct_ep_h tl_ep, uct_ep_addr_t *addr) {
  return UCS_ERR_UNSUPPORTED;
}

int uct_ptl_am_ep_is_connected(const uct_ep_h tl_ep,
                               const uct_ep_is_connected_params_t *params) {
  return 0;
}

ucs_status_t uct_ptl_am_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *n,
                                       unsigned flags) {
  return UCS_ERR_UNSUPPORTED;
}

void uct_ptl_am_ep_pending_purge(uct_ep_h ep, uct_pending_purge_callback_t cb,
                                 void *arg) {
  return;
}

ucs_status_t uct_ptl_am_ep_check(uct_ep_h tl_ep, unsigned flags,
                                 uct_completion_t *comp) {
  return UCS_ERR_UNSUPPORTED;
}

UCS_CLASS_INIT_FUNC(uct_ptl_am_ep_t, const uct_ep_params_t *params) {
  uct_ptl_am_iface_t *iface = ucs_derived_of(params->iface, uct_ptl_am_iface_t);
  uct_ptl_am_iface_addr_t *addr = (uct_ptl_am_iface_addr_t *)params->iface_addr;

  UCS_CLASS_CALL_SUPER_INIT(uct_ptl_ep_t, &iface->super, params);

  self->am_mp = &iface->am_mp;
  self->rma_mp = &iface->rma_mp;
  self->am_md = &iface->am_mmd;
  self->rma_md = iface->rma_mmd;

  self->am_pti = addr->am_pti;
  self->rma_pti = addr->rma_pti;

  return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ptl_am_ep_t) {
  ucs_debug("destroy ptl ep %p", self);
  return;
}

UCS_CLASS_DEFINE(uct_ptl_am_ep_t, uct_ptl_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_ptl_am_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_ptl_am_ep_t, uct_ep_t);
