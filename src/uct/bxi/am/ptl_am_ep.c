#include "ptl_am_ep.h"
#include "ptl_am_iface.h"
#include "ptl_types.h"

#include <sys/types.h>
#include <time.h>
#include <uct/base/uct_log.h>

ucs_status_t uct_ptl_am_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t hdr,
                                    const void *buffer, unsigned length)
{
  ucs_status_t        rc;
  ptl_match_bits_t    am_hdr = 0;
  uct_ptl_am_ep_t    *ep     = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface  = ucs_derived_of(tl_ep->iface, uct_ptl_am_iface_t);

  return UCS_ERR_UNSUPPORTED;

  ucs_assert(length <= iface->super.config.max_short);

  UCT_PTL_HDR_SET(am_hdr, 0, id, UCT_PTL_AM_SHORT);
  ep->am_mmd->seqn++;

  rc = uct_ptl_wrap(PtlPut(ep->am_mmd->mdh, (ptl_size_t)buffer, length,
                           PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.am_pti, am_hdr, 0, NULL, hdr));

  return rc;
}

ucs_status_t uct_ptl_am_ep_am_short_iov(uct_ep_h tl_ep, uint8_t id,
                                        const uct_iov_t *iov, size_t iovcnt)
{
  ucs_status_t        rc;
  ptl_match_bits_t    am_hdr = 0;
  uct_ptl_am_ep_t    *ep     = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface  = ucs_derived_of(tl_ep->iface, uct_ptl_am_iface_t);

  return UCS_ERR_UNSUPPORTED;

  ucs_assert(iovcnt == 1 && iov->length <= iface->super.config.max_short);

  UCT_PTL_HDR_SET(am_hdr, 0, id, UCT_PTL_AM_BCOPY);
  ep->am_mmd->seqn++;

  rc = uct_ptl_wrap(PtlPut(ep->am_mmd->mdh, (ptl_size_t)iov->buffer,
                           iov->length, PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.am_pti, am_hdr, 0, NULL, 0));

  return rc;
}

ssize_t uct_ptl_am_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id,
                               uct_pack_callback_t pack, void *arg,
                               unsigned flags)
{
  ucs_status_t        rc    = UCS_OK;
  ptl_match_bits_t    hdr   = 0;
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  uct_ptl_op_t       *op;
  ssize_t             size = 0;

  UCT_CHECK_AM_ID(id);

  if (ep->super.conn_state == UCT_PTL_EP_CONN_CLOSED) {
    rc = UCS_ERR_TIMED_OUT;
    goto err;
  }

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_AM_BCOPY, 1, NULL, NULL, &iface->super,
                             &ep->super, ep->am_mmd, &op);
  if (rc != UCS_OK) {
    size = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op->seqn = ucs_atomic_fadd64(&ep->am_mmd->seqn, 1);
  op->pti  = ep->iface_addr.am_pti;
  size     = pack(op->buffer, arg);
  if (size < 0) {
    goto err;
  }

  UCT_PTL_HDR_SET(hdr, 0, id, UCT_PTL_AM_BCOPY);
  rc = uct_ptl_wrap(PtlPut(ep->am_mmd->mdh, (ptl_size_t)op->buffer, size,
                           PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.am_pti, hdr, 0, op, 0));

  if (rc != UCS_OK) {
    ucs_atomic_fadd64(&ep->am_mmd->seqn, -1);
    ucs_mpool_put(op->buffer);
    ucs_mpool_put(op);
    size = UCS_ERR_IO_ERROR;
    goto err;
  }

  ucs_debug("PTL: send am bcopy. op=%p, seqn=%lu, length=%lu", op, op->seqn,
            size);

  ucs_queue_push(&ep->am_mmd->opq, &op->elem);

  uct_ptl_iface_trace_am(ucs_derived_of(tl_ep->iface, uct_ptl_am_iface_t),
                         UCT_AM_TRACE_TYPE_SEND, id, op->buffer, size);
err:
  return size;
}

ucs_status_t uct_ptl_am_ep_am_zcopy(uct_ep_h tl_ep, uint8_t id,
                                    const void *header, unsigned header_length,
                                    const uct_iov_t *iov, size_t iovcnt,
                                    unsigned flags, uct_completion_t *comp)
{
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
                                     uct_rkey_t rkey)
{
  ucs_status_t        rc;
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  uct_ptl_op_t       *op;

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_RMA_PUT_SHORT, 0, NULL, NULL,
                             &iface->super, &ep->super, ep->rma_mmd, &op);
  if (rc != UCS_OK) {
    goto err;
  }

  op->seqn = ucs_atomic_fadd64(&ep->rma_mmd->seqn, 1);
  op->pti  = ep->iface_addr.rma_pti;
  if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_DATA)) {
    char buf[256] = {0};
    uct_log_data(__FILE__, __LINE__, __func__, buf);
  }

  rc = uct_ptl_wrap(PtlPut(ep->rma_mmd->mdh, (ptl_size_t)buffer, length,
                           PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.rma_pti, 0, remote_addr, NULL, 0));

  if (rc != UCS_OK) {
    ucs_atomic_fadd64(&ep->rma_mmd->seqn, -1);
    ucs_mpool_put(op);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  ucs_queue_push(&ep->rma_mmd->opq, &op->elem);

err:
  return rc;
}

ssize_t uct_ptl_am_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                                void *arg, uint64_t remote_addr,
                                uct_rkey_t rkey)
{
  ucs_status_t        rc    = UCS_OK; // FIXME: remove rc?
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  uct_ptl_op_t       *op;
  ssize_t             size = 0;

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_RMA_PUT_BCOPY, 1, NULL, NULL,
                             &iface->super, &ep->super, ep->rma_mmd, &op);
  if (rc != UCS_OK) {
    size = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op->seqn = ucs_atomic_fadd64(&ep->rma_mmd->seqn, 1);
  op->pti  = ep->iface_addr.rma_pti;
  size     = pack_cb(op->buffer, arg);
  if (size < 0) {
    goto err;
  }

  if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_DATA)) {
    char buf[256] = {0};
    uct_log_data(__FILE__, __LINE__, __func__, buf);
  }

  ucs_debug("PTL: put bcopy. op=%p, seqn=%lu, length=%lu", op, op->seqn, size);
  rc = uct_ptl_wrap(PtlPut(ep->rma_mmd->mdh, (ptl_size_t)op->buffer, size,
                           PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.rma_pti, 0, remote_addr, NULL, 0));

  if (rc != UCS_OK) {
    ucs_atomic_fadd64(&ep->rma_mmd->seqn, -1);
    ucs_mpool_put(op->buffer);
    ucs_mpool_put(op);
    size = UCS_ERR_IO_ERROR;
    goto err;
  }

  ucs_queue_push(&ep->rma_mmd->opq, &op->elem);

err:
  return size;
}

ucs_status_t uct_ptl_am_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                     size_t iovcnt, uint64_t remote_addr,
                                     uct_rkey_t rkey, uct_completion_t *comp)
{
  ucs_status_t        rc;
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  uct_ptl_op_t       *op;

  ucs_assert(iovcnt == 1);

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_RMA_PUT_ZCOPY, 0, comp, NULL,
                             &iface->super, &ep->super, ep->rma_mmd, &op);
  if (rc != UCS_OK) {
    goto err;
  }

  op->seqn = ucs_atomic_fadd64(&ep->rma_mmd->seqn, 1);
  op->pti  = ep->iface_addr.rma_pti;
  if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_DATA)) {
    char buf[256] = {0};
    uct_log_data(__FILE__, __LINE__, __func__, buf);
  }

  ucs_debug("PTL: put zcopy. op=%p, seqn=%lu, length=%lu", op, op->seqn,
            iov->length);
  rc = uct_ptl_wrap(PtlPut(ep->rma_mmd->mdh, (ptl_size_t)iov[0].buffer,
                           iov[0].length, PTL_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.rma_pti, 0, remote_addr, op, 0));

  if (rc != UCS_OK) {
    ucs_atomic_fadd64(&ep->rma_mmd->seqn, -1);
    ucs_mpool_put(op);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  rc = UCS_INPROGRESS;
  ucs_queue_push(&ep->rma_mmd->opq, &op->elem);

err:
  return rc;
}

ucs_status_t uct_ptl_am_ep_get_bcopy(uct_ep_h              tl_ep,
                                     uct_unpack_callback_t unpack_cb, void *arg,
                                     size_t length, uint64_t remote_addr,
                                     uct_rkey_t rkey, uct_completion_t *comp)
{
  ucs_status_t        rc    = UCS_OK; // FIXME: remove rc?
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  uct_ptl_op_t       *op;

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_RMA_GET_BCOPY, 1, comp, NULL,
                             &iface->super, &ep->super, ep->rma_mmd, &op);
  if (rc != UCS_OK) {
    goto err;
  }

  op->size             = length;
  op->seqn             = ucs_atomic_fadd64(&ep->rma_mmd->seqn, 1);
  op->get_bcopy.unpack = unpack_cb;
  op->get_bcopy.arg    = arg;
  op->pti              = ep->iface_addr.rma_pti;

  if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_DATA)) {
    char buf[256] = {0};
    uct_log_data(__FILE__, __LINE__, __func__, buf);
  }

  ucs_debug("PTL: get bcopy. op=%p, seqn=%lu", op, op->seqn);
  rc = uct_ptl_wrap(PtlGet(ep->rma_mmd->mdh, (ptl_size_t)op->buffer, length,
                           ep->super.dev_addr.pid, ep->iface_addr.rma_pti, 0,
                           remote_addr, NULL));

  if (rc != UCS_OK) {
    ucs_atomic_fadd64(&ep->rma_mmd->seqn, -1);
    ucs_mpool_put(op->buffer);
    ucs_mpool_put(op);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  rc = UCS_INPROGRESS;
  ucs_queue_push(&ep->rma_mmd->opq, &op->elem);
err:
  return rc;
}

ucs_status_t uct_ptl_am_ep_get_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                     size_t iovcnt, uint64_t remote_addr,
                                     uct_rkey_t rkey, uct_completion_t *comp)
{
  ucs_status_t        rc;
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  uct_ptl_op_t       *op;

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_RMA_GET_ZCOPY, 0, comp, NULL,
                             &iface->super, &ep->super, ep->rma_mmd, &op);
  if (rc != UCS_OK) {
    goto err;
  }

  op->seqn = ucs_atomic_fadd64(&ep->rma_mmd->seqn, 1);
  op->pti  = ep->iface_addr.rma_pti;
  if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_DATA)) {
    char buf[256] = {0};
    uct_log_data(__FILE__, __LINE__, __func__, buf);
  }

  ucs_debug("PTL: get zcopy. op=%p, seqn=%lu, size=%lu, local addr=%p, remote "
            "addr=%p",
            op, op->seqn, iov[0].length, iov[0].buffer, (void *)remote_addr);
  rc = uct_ptl_wrap(PtlGet(ep->rma_mmd->mdh, (ptl_size_t)iov[0].buffer,
                           iov[0].length, ep->super.dev_addr.pid,
                           ep->iface_addr.rma_pti, 0, remote_addr, NULL));

  if (rc != UCS_OK) {
    ucs_mpool_put(op);
    ucs_atomic_fadd64(&ep->rma_mmd->seqn, -1);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  rc = UCS_INPROGRESS;
  ucs_queue_push(&ep->rma_mmd->opq, &op->elem);

err:
  return rc;
}

ucs_status_t uct_ptl_am_ep_tag_eager_short(uct_ep_h ep, uct_tag_t tag,
                                           const void *data, size_t length)
{
  return UCS_ERR_NOT_IMPLEMENTED;
}

ssize_t uct_ptl_am_ep_tag_eager_bcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                      uint64_t imm, uct_pack_callback_t pack_cb,
                                      void *arg, unsigned flags)
{
  ucs_status_t        rc    = UCS_OK;
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  uct_ptl_op_t       *op;
  ssize_t             size = 0;

  if (ep->super.conn_state == UCT_PTL_EP_CONN_CLOSED) {
    rc = UCS_ERR_TIMED_OUT;
    goto err;
  }

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_TAG_BCOPY, 1, NULL, NULL, &iface->super,
                             &ep->super, ep->am_mmd, &op);
  if (rc != UCS_OK) {
    size = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op->seqn = ucs_atomic_fadd64(&ep->am_mmd->seqn, 1);
  op->pti  = ep->iface_addr.tag_pti;
  size     = pack_cb(op->buffer, arg);
  if (size < 0) {
    goto err;
  }

  ucs_debug("PTL: ep tag bcopy. iface pti=%d, tag=0x%016lx, imm=0x%016lx, "
            "op=%p, op id=%lu",
            iface->tag_rq.pti, tag, imm, op, op->seqn);

  rc = uct_ptl_wrap(PtlPut(ep->am_mmd->mdh, (ptl_size_t)op->buffer, size,
                           PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.tag_pti, tag, 0, op, imm));

  if (rc != UCS_OK) {
    ucs_atomic_fadd64(&ep->am_mmd->seqn, -1);
    ucs_mpool_put(op->buffer);
    ucs_mpool_put(op);
    size = UCS_ERR_IO_ERROR;
    goto err;
  }

  ucs_queue_push(&ep->am_mmd->opq, &op->elem);

err:
  return size;
}

ucs_status_t uct_ptl_am_ep_tag_eager_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                           uint64_t imm, const uct_iov_t *iov,
                                           size_t iovcnt, unsigned flags,
                                           uct_completion_t *comp)
{

  ucs_status_t        rc    = UCS_OK;
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  uct_ptl_op_t       *op;
  uct_ptl_oop_ctx_t  *oop_ctx;

  if (ep->super.conn_state == UCT_PTL_EP_CONN_CLOSED) {
    rc = UCS_ERR_TIMED_OUT;
    goto err;
  }

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_TAG_ZCOPY, 0, comp, NULL, &iface->super,
                             &ep->super, ep->am_mmd, &op);
  if (rc != UCS_OK) {
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }
  op->seqn = ucs_atomic_fadd64(&ep->am_mmd->seqn, 1);
  op->pti  = ep->iface_addr.tag_pti;

  ucs_debug(
          "PTL: ep tag zcopy. iface pti=%d, tag=0x%016lx, imm=0x%016lx, op=%p",
          iface->tag_rq.pti, tag, imm, op);
  if (flags & UCT_TAG_OFFLOAD_OPERATION) {
    oop_ctx = ucs_derived_of(comp->oop_ctx, uct_ptl_oop_ctx_t);
    ucs_assert(!PtlHandleIsEqual(oop_ctx->cth, PTL_INVALID_HANDLE));

    rc = uct_ptl_wrap(PtlTriggeredPut(
            ep->am_mmd->mdh, (ptl_size_t)iov->buffer, iov->length,
            PTL_CT_ACK_REQ, ep->super.dev_addr.pid, ep->iface_addr.tag_pti, tag,
            0, op, imm, oop_ctx->cth, oop_ctx->threshold));
  } else {
    rc = uct_ptl_wrap(PtlPut(ep->am_mmd->mdh, (ptl_size_t)iov->buffer,
                             iov->length, PTL_CT_ACK_REQ,
                             ep->super.dev_addr.pid, ep->iface_addr.tag_pti,
                             tag, 0, op, imm));
  }

  if (rc != UCS_OK) {
    ucs_atomic_fadd64(&ep->am_mmd->seqn, -1);
    ucs_mpool_put(op->buffer);
    ucs_mpool_put(op);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  ucs_queue_push(&ep->am_mmd->opq, &op->elem);

  rc = UCS_INPROGRESS;

err:
  return rc;
}

static inline size_t uct_ptl_am_pack_rndv(void *src, uint64_t remote_addr,
                                          size_t length, const void *header,
                                          unsigned header_length)
{
  size_t                 len = 0;
  uct_ptl_am_hdr_rndv_t *hdr = src;

  hdr->remote_addr    = remote_addr;
  hdr->length         = length;
  hdr->header_length  = header_length;
  len                += sizeof(*hdr);

  memcpy(hdr + 1, header, header_length);

  return len + header_length;
}

ucs_status_ptr_t uct_ptl_am_ep_tag_rndv_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                              const void      *header,
                                              unsigned         header_length,
                                              const uct_iov_t *iov,
                                              size_t iovcnt, unsigned flags,
                                              uct_completion_t *comp)
{
  ucs_status_t        rc    = UCS_OK;
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  ptl_hdr_data_t      hdr   = 0;
  uct_ptl_op_t       *op    = NULL;
  ptl_me_t            me;

  assert(iovcnt <= 1);

  if (iface->tm.num_get_tags == 0) {
    op = (uct_ptl_op_t *)UCS_ERR_NO_RESOURCE;
    goto err;
  }

  if (ep->super.conn_state == UCT_PTL_EP_CONN_CLOSED) {
    rc = UCS_ERR_TIMED_OUT;
    goto err;
  }

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_TAG_BCOPY, 1, comp, NULL, &iface->super,
                             &ep->super, ep->am_mmd, &op);
  if (rc != UCS_OK) {
    op = (uct_ptl_op_t *)UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op->tag.meh   = PTL_INVALID_HANDLE;
  op->type      = UCT_PTL_OP_RMA_PUT_ZCOPY_TAG;
  op->pti       = ep->iface_addr.tag_pti;
  op->tag.flags = 0;
  op->seqn      = ucs_atomic_fadd64(&ep->am_mmd->seqn, 1);
  op->size      = uct_ptl_am_pack_rndv(op->buffer, (uint64_t)iov[0].buffer,
                                       iov[0].length, header, header_length);
  op->tag.tag   = ucs_atomic_fadd32(&iface->tm.rndv_tag, 1);

  me = (ptl_me_t){
          .ct_handle   = PTL_CT_NONE,
          .ignore_bits = 0,
          .match_bits  = op->tag.tag,
          .match_id    = {.phys.nid = PTL_NID_ANY, .phys.pid = PTL_PID_ANY},
          .min_free    = 0,
          .length      = iov[0].length,
          .start       = iov[0].buffer,
          .uid         = PTL_UID_ANY,
          .options     = PTL_ME_OP_GET | PTL_ME_USE_ONCE |
                     PTL_ME_EVENT_LINK_DISABLE | PTL_ME_EVENT_UNLINK_DISABLE,
  };

  iface->tm.num_get_tags--;
  rc = uct_ptl_wrap(PtlMEAppend(uct_ptl_iface_md(&iface->super)->nih,
                                iface->tag_rq.pti, &me, PTL_PRIORITY_LIST, op,
                                &op->tag.meh));
  if (rc != UCS_OK) {
    return (ucs_status_ptr_t)UCS_ERR_NO_RESOURCE;
  }

  UCT_PTL_HDR_SET(hdr, op->tag.tag, iface->tag_rq.pti, UCT_PTL_RNDV_HW_MAGIC);
  rc = uct_ptl_wrap(PtlPut(ep->am_mmd->mdh, (ptl_size_t)op->buffer, op->size,
                           PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.tag_pti, tag, 0, op, hdr));

  if (rc != UCS_OK) {
    ucs_atomic_fadd64(&ep->am_mmd->seqn, -1);
    ucs_mpool_put(op->buffer);
    ucs_mpool_put(op);
    uct_ptl_wrap(PtlMEUnlink(op->tag.meh));
    return (ucs_status_ptr_t)UCS_ERR_IO_ERROR;
  }

  ucs_debug("PTL: ep tag rndv zcopy. iface src pti=%d, dest pti=%d, "
            "tag=0x%016lx, op=%p, size=%lu, op id=%lu, num get tags=%d",
            iface->tag_rq.pti, ep->iface_addr.tag_pti, tag, op, iov[0].length,
            op->seqn, iface->tm.num_get_tags);

  ucs_queue_push(&ep->am_mmd->opq, &op->elem);
err:
  return (ucs_status_ptr_t)op;
}

ucs_status_t uct_ptl_am_ep_tag_rndv_cancel(uct_ep_h tl_ep, void *tl_op)
{
  uct_ptl_op_t       *op    = (uct_ptl_op_t *)tl_op;
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);

  if (!PtlHandleIsEqual(op->tag.meh, PTL_INVALID_HANDLE)) {
    uct_ptl_wrap(PtlMEUnlink(op->tag.meh));
    iface->tm.num_get_tags++;
  }

  ucs_debug("PTL: (C) op complete. id=%lu, type=%d", op->seqn, op->type);
  ucs_mpool_put(op);
  return UCS_OK;
}

ucs_status_t uct_ptl_am_ep_tag_rndv_request(uct_ep_h tl_ep, uct_tag_t tag,
                                            const void *header,
                                            unsigned    header_length,
                                            unsigned    flags)
{
  ucs_status_t        rc    = UCS_OK;
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  ptl_hdr_data_t      hdr   = 0;
  uct_ptl_op_t       *op    = NULL;

  if (ep->super.conn_state == UCT_PTL_EP_CONN_CLOSED) {
    rc = UCS_ERR_TIMED_OUT;
    goto err;
  }

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_TAG_BCOPY, 1, NULL, NULL, &iface->super,
                             &ep->super, ep->am_mmd, &op);
  if (rc != UCS_OK) {
    goto err;
  }

  op->type      = UCT_PTL_OP_RMA_PUT_RNDV_REQ;
  op->tag.flags = 0;
  op->seqn      = ucs_atomic_fadd64(&ep->am_mmd->seqn, 1);
  op->size      = header_length;
  op->pti       = ep->iface_addr.tag_pti;
  memcpy(op->buffer, header, header_length);

  UCT_PTL_HDR_SET(hdr, 0, iface->tag_rq.pti, UCT_PTL_RNDV_SW_MAGIC);
  rc = uct_ptl_wrap(PtlPut(ep->am_mmd->mdh, (ptl_size_t)op->buffer, op->size,
                           PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.tag_pti, tag, 0, op, hdr));

  if (rc != UCS_OK) {
    ucs_atomic_fadd64(&ep->am_mmd->seqn, -1);
    ucs_mpool_put(op->buffer);
    ucs_mpool_put(op);
    return UCS_ERR_IO_ERROR;
  }

  ucs_debug("PTL: ep tag rndv request. iface pti=%d, tag=0x%016lx, op=%p, "
            "buffer=%p, size=%lu, id=%lu",
            iface->tag_rq.pti, tag, op, op->buffer, op->size, op->seqn);

  ucs_queue_push(&ep->am_mmd->opq, &op->elem);

err:
  return rc;
}

ucs_status_t uct_ptl_am_iface_tag_recv_zcopy(uct_iface_h tl_iface,
                                             uct_tag_t tag, uct_tag_t tag_mask,
                                             const uct_iov_t   *iov,
                                             size_t             iovcnt,
                                             uct_tag_context_t *ctx)
{
  ucs_status_t        rc = UCS_OK;
  int                 ret;
  ptl_me_t            me;
  uct_ptl_am_iface_t *iface    = ucs_derived_of(tl_iface, uct_ptl_am_iface_t);
  ptl_handle_ct_t     cth      = PTL_CT_NONE;
  unsigned            ct_flags = 0;
  uct_ptl_oop_ctx_t  *oop_ctx;
  uct_ptl_op_t       *op;
  static uint32_t     seqn = 0;

  ucs_assert(iov && iovcnt == 1);
  UCT_PTL_CHECK_TAG(iface);

  ret = uct_ptl_am_iface_tag_add_to_hash(iface, iov[0].buffer);
  if (ret != UCS_OK) {
    return ret;
  }

  if (ctx->oop_ctx != NULL && ctx->flags == UCT_TAG_OFFLOAD_OPERATION) {
    /* User specified a context to offload operations. */
    oop_ctx = ucs_derived_of(ctx->oop_ctx, uct_ptl_oop_ctx_t);
    cth     = oop_ctx->cth;
    oop_ctx->threshold++;
    ct_flags = PTL_ME_EVENT_CT_COMM;
  }

  me = (ptl_me_t){
          .ct_handle   = cth,
          .ignore_bits = ~tag_mask,
          .match_bits  = tag,
          .match_id    = {.phys.nid = PTL_NID_ANY, .phys.pid = PTL_PID_ANY},
          .min_free    = 0,
          .length      = iov[0].length,
          .start       = iov[0].buffer,
          .uid         = PTL_UID_ANY,
          .options     = PTL_ME_OP_PUT | PTL_ME_USE_ONCE |
                     PTL_ME_EVENT_OVER_DISABLE | PTL_ME_EVENT_LINK_DISABLE |
                     PTL_ME_EVENT_UNLINK_DISABLE | ct_flags,
  };

  op = ucs_mpool_get(&iface->tm.recv_ops_mp);
  if (op == NULL) {
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }
  op->comp       = NULL;
  op->ep         = NULL;
  op->type       = UCT_PTL_OP_RECV;
  op->buffer     = NULL;
  op->tag.ctx    = ctx;
  op->tag.flags  = 0;
  op->tag.tag    = tag;
  op->tag.buffer = iov[0].buffer;
  op->size       = iov[0].length;
  op->seqn       = seqn++;

  iface->tm.num_tags--;
  rc = uct_ptl_wrap(PtlMEAppend(uct_ptl_iface_md(&iface->super)->nih,
                                iface->tag_rq.pti, &me, PTL_PRIORITY_LIST, op,
                                &op->tag.meh));

  ucs_debug(
          "PTL: recv tag zcopy. iface pti=%d, tag=0x%016lx, ign tag=0x%016lx, "
          "num tags=%d, op=%p, buffer=%p, size=%lu, op id=%lu",
          iface->tag_rq.pti, tag, tag_mask, iface->tm.num_tags, op,
          iov[0].buffer, iov[0].length, op->seqn);

  *(uct_ptl_op_t **)ctx->priv = op;

  return rc;

err:
  uct_ptl_am_iface_tag_del_from_hash(iface, iov[0].buffer);
  return rc;
}

ucs_status_t uct_ptl_am_iface_tag_recv_cancel(uct_iface_h        tl_iface,
                                              uct_tag_context_t *ctx, int force)
{
  ucs_status_t        rc    = UCS_OK;
  uct_ptl_op_t       *op    = *(uct_ptl_op_t **)ctx->priv;
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_iface, uct_ptl_am_iface_t);

  ucs_assert(op->type == UCT_PTL_OP_RECV);

  //NOTE: there is no error checking here because the ME might have been
  //unlinked already during the receive call.
  //FIXME: actually no. Recheck
  PtlMEUnlink(op->tag.meh);

  iface->tm.num_tags++;
  if (!force) {
    op->tag.cancel = 1;
  }

  ucs_debug("PTL: recv tag cancel. iface pti=%d, tag=0x%016lx, "
            "num tags=%d, op=%p, buffer=%p, size=%lu, op id=%lu",
            iface->tag_rq.pti, op->tag.tag, iface->tm.num_tags, op,
            op->tag.buffer, op->size, op->seqn);

  uct_ptl_am_iface_tag_del_from_hash(iface, op->tag.buffer);
  if (force) {
    ucs_mpool_put(op);
  } else {
    // Push it to cancel queue to make it complete if necessary during the
    // progress phase. This is necessary to pass some UCT test...
    ucs_queue_push(&iface->tm.canceled_ops, &op->elem);
  }
err:
  return rc;
}

void uct_ptl_am_iface_tag_recv_overflow(uct_iface_h tl_iface)
{
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_iface, uct_ptl_am_iface_t);

  iface->tm.recv_tried_offload++;
}

ucs_status_t uct_ptl_am_iface_tag_create_oop_ctx(uct_iface_h    tl_iface,
                                                 uct_oop_ctx_h *oop_ctx_p)
{
  ucs_status_t        rc;
  uct_ptl_oop_ctx_t  *oop_ctx;
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_iface, uct_ptl_am_iface_t);

  oop_ctx = ucs_malloc(sizeof(uct_ptl_oop_ctx_t), "ptl_oop_ctx");
  if (oop_ctx == NULL) {
    rc = UCS_ERR_NO_MEMORY;
    goto err;
  }

  if (iface->tm.oop_ctx_cnt == 0) {
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }
  oop_ctx->threshold     = 0;
  oop_ctx->super.ref_cnt = 0;

  rc = uct_ptl_wrap(
          PtlCTAlloc(uct_ptl_iface_md(&iface->super)->nih, &oop_ctx->cth));
  if (rc != UCS_OK) {
    goto err_free_oop_ctx;
  }

  iface->tm.oop_ctx_cnt--;

  *oop_ctx_p = (uct_oop_ctx_h)oop_ctx;

  return rc;

err_free_oop_ctx:
  ucs_free(oop_ctx);
err:
  return rc;
}

void uct_ptl_am_iface_tag_delete_oop_ctx(uct_iface_h   tl_iface,
                                         uct_oop_ctx_h tl_oop_ctx)
{
  uct_ptl_oop_ctx_t  *oop_ctx = (uct_ptl_oop_ctx_t *)tl_oop_ctx;
  uct_ptl_am_iface_t *iface   = ucs_derived_of(tl_iface, uct_ptl_am_iface_t);

  ucs_assert(oop_ctx->super.ref_cnt >= 0);
  ucs_assert(!PtlHandleIsEqual(oop_ctx->cth, PTL_INVALID_HANDLE));

  if (--oop_ctx->super.ref_cnt <= 0) {
    uct_ptl_wrap(PtlCTFree(oop_ctx->cth));

    ucs_free(oop_ctx);

    iface->tm.oop_ctx_cnt++;
  }
}

static ucs_status_t
uct_ptl_am_ep_atomic_post_common(uct_ep_h tl_ep, unsigned opcode,
                                 uint64_t value, size_t size, ptl_datatype_t dt,
                                 uint64_t remote_addr, uct_rkey_t rkey)
{
  ucs_status_t        rc;
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  uct_ptl_op_t       *op;

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_ATOMIC, 0, NULL, NULL, &iface->super,
                             &ep->super, ep->rma_mmd, &op);
  if (rc != UCS_OK) {
    goto err;
  }

  op->seqn      = ucs_atomic_fadd64(&ep->rma_mmd->seqn, 1);
  op->ato.value = value;

  rc = uct_ptl_wrap(PtlAtomic(ep->rma_mmd->mdh, (uint64_t)&op->ato.value, size,
                              PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                              ep->iface_addr.rma_pti, 0, remote_addr, NULL, 0,
                              uct_ptl_atomic_op_table[opcode], dt));

  if (rc != UCS_OK) {
    ucs_mpool_put(op);
    ucs_atomic_fadd64(&ep->rma_mmd->seqn, -1);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  ucs_queue_push(&ep->rma_mmd->opq, &op->elem);

err:
  return rc;
}

static ucs_status_t
uct_ptl_am_ep_atomic_fetch_common(uct_ep_h tl_ep, unsigned opcode,
                                  uint64_t value, uint64_t *result, size_t size,
                                  ptl_datatype_t dt, uint64_t remote_addr,
                                  uct_rkey_t rkey, uct_completion_t *comp)
{
  ucs_status_t        rc;
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  uct_ptl_op_t       *op;

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_ATOMIC, 0, comp, NULL, &iface->super,
                             &ep->super, ep->rma_mmd, &op);
  if (rc != UCS_OK) {
    goto err;
  }

  op->seqn      = ucs_atomic_fadd64(&ep->rma_mmd->seqn, 1);
  op->ato.value = value;

  ucs_debug("PTL: fetch start. op=%p, seqn=%lu", op, op->seqn);
  rc = uct_ptl_wrap(PtlFetchAtomic(ep->rma_mmd->mdh, (uint64_t)result,
                                   ep->rma_mmd->mdh, (uint64_t)&op->ato.value,
                                   size, ep->super.dev_addr.pid,
                                   ep->iface_addr.rma_pti, 0, remote_addr, NULL,
                                   0, uct_ptl_atomic_op_table[opcode], dt));

  if (rc != UCS_OK) {
    ucs_atomic_fadd64(&ep->rma_mmd->seqn, -1);
    ucs_mpool_put(op);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  rc = UCS_INPROGRESS;
  ucs_queue_push(&ep->rma_mmd->opq, &op->elem);

err:
  return rc;
}

static ucs_status_t
uct_ptl_am_ep_atomic_cswap_common(uct_ep_h tl_ep, uint64_t compare,
                                  uint64_t swap, size_t size, ptl_datatype_t dt,
                                  uint64_t remote_addr, uct_rkey_t rkey,
                                  uint64_t *result, uct_completion_t *comp)
{
  ucs_status_t        rc;
  uct_ptl_am_ep_t    *ep    = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = uct_ptl_ep_iface(ep, uct_ptl_am_iface_t);
  uct_ptl_op_t       *op;

  rc = uct_ptl_ep_prepare_op(UCT_PTL_OP_ATOMIC, 0, comp, NULL, &iface->super,
                             &ep->super, ep->rma_mmd, &op);
  if (rc != UCS_OK) {
    goto err;
  }

  op->seqn        = ucs_atomic_fadd64(&ep->rma_mmd->seqn, 1);
  op->ato.value   = swap;
  op->ato.compare = compare;

  rc = uct_ptl_wrap(PtlSwap(ep->rma_mmd->mdh, (uint64_t)result,
                            ep->rma_mmd->mdh, (uint64_t)&op->ato.value, size,
                            ep->super.dev_addr.pid, ep->iface_addr.rma_pti, 0,
                            remote_addr, NULL, 0, &op->ato.compare, PTL_CSWAP,
                            dt));

  if (rc != UCS_OK) {
    ucs_atomic_fadd64(&ep->rma_mmd->seqn, -1);
    ucs_mpool_put(op);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  rc = UCS_INPROGRESS;
  ucs_queue_push(&ep->rma_mmd->opq, &op->elem);

err:
  return rc;
}

ucs_status_t uct_ptl_am_ep_atomic_cswap32(uct_ep_h tl_ep, uint32_t compare,
                                          uint32_t swap, uint64_t remote_addr,
                                          uct_rkey_t rkey, uint32_t *result,
                                          uct_completion_t *comp)
{
  return uct_ptl_am_ep_atomic_cswap_common(
          tl_ep, (uint64_t)compare, (uint64_t)swap, sizeof(uint32_t),
          PTL_UINT32_T, remote_addr, rkey, (uint64_t *)result, comp);
}

ucs_status_t uct_ptl_am_ep_atomic32_post(uct_ep_h tl_ep, unsigned opcode,
                                         uint32_t value, uint64_t remote_addr,
                                         uct_rkey_t rkey)
{
  return uct_ptl_am_ep_atomic_post_common(tl_ep, opcode, value,
                                          sizeof(uint32_t), PTL_UINT32_T,
                                          remote_addr, rkey);
}

ucs_status_t uct_ptl_am_ep_atomic32_fetch(uct_ep_h tl_ep, unsigned opcode,
                                          uint32_t value, uint32_t *result,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp)
{
  return uct_ptl_am_ep_atomic_fetch_common(
          tl_ep, opcode, (uint64_t)value, (uint64_t *)result, sizeof(uint32_t),
          PTL_UINT32_T, remote_addr, rkey, comp);
}

ucs_status_t uct_ptl_am_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare,
                                          uint64_t swap, uint64_t remote_addr,
                                          uct_rkey_t rkey, uint64_t *result,
                                          uct_completion_t *comp)
{
  return uct_ptl_am_ep_atomic_cswap_common(tl_ep, compare, swap,
                                           sizeof(uint64_t), PTL_UINT64_T,
                                           remote_addr, rkey, result, comp);
}

ucs_status_t uct_ptl_am_ep_atomic64_post(uct_ep_h tl_ep, unsigned opcode,
                                         uint64_t value, uint64_t remote_addr,
                                         uct_rkey_t rkey)
{
  return uct_ptl_am_ep_atomic_post_common(tl_ep, opcode, value,
                                          sizeof(uint64_t), PTL_UINT64_T,
                                          remote_addr, rkey);
}

ucs_status_t uct_ptl_am_ep_atomic64_fetch(uct_ep_h        tl_ep,
                                          uct_atomic_op_t opcode,
                                          uint64_t value, uint64_t *result,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp)
{
  return uct_ptl_am_ep_atomic_fetch_common(tl_ep, opcode, value, result,
                                           sizeof(uint64_t), PTL_UINT64_T,
                                           remote_addr, rkey, comp);
}

ucs_status_t uct_ptl_am_ep_flush(uct_ep_h tl_ep, unsigned flags,
                                 uct_completion_t *comp)
{
  return uct_ptl_am_iface_flush(tl_ep->iface, flags, comp);
}

ucs_status_t uct_ptl_am_ep_fence(uct_ep_h tl_ep, unsigned flags)
{
  return uct_ptl_am_iface_fence(tl_ep->iface, flags);
}

void uct_ptl_am_ep_post_check(uct_ep_h tl_ep)
{
  return;
}

ucs_status_t uct_ptl_am_ep_get_address(uct_ep_h tl_ep, uct_ep_addr_t *addr)
{
  uct_ptl_am_ep_t      *ep       = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_ep_addr_t *ptl_addr = (uct_ptl_am_ep_addr_t *)addr;

  ptl_addr->super.dev_addr = ep->super.dev_addr;
  ptl_addr->iface_addr     = ep->iface_addr;

  return UCS_OK;
}

int uct_ptl_am_ep_is_connected(const uct_ep_h                      tl_ep,
                               const uct_ep_is_connected_params_t *params)
{
  int                      is_connected = 1;
  uct_ptl_am_ep_t         *ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_device_addr_t   *dest_device_addr;
  uct_ptl_am_iface_addr_t *dest_iface_addr;

  UCT_EP_IS_CONNECTED_CHECK_DEV_IFACE_ADDRS(params);

  dest_device_addr = (uct_ptl_device_addr_t *)params->device_addr;
  dest_iface_addr  = (uct_ptl_am_iface_addr_t *)params->iface_addr;

  if (!uct_ptl_iface_cmp_device_addr(&ep->super.dev_addr, dest_device_addr) ||
      !uct_ptl_am_iface_cmp_iface_addr(&ep->iface_addr, dest_iface_addr)) {
    is_connected = 0;
  }

  return is_connected;
}

ucs_status_t uct_ptl_am_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *req,
                                       unsigned flags)
{
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_ptl_am_iface_t);

  if (!ucs_mpool_is_empty(&iface->super.ops_mp) &&
      !ucs_mpool_is_empty(&iface->super.copyin_mp) &&
      iface->tm.num_get_tags > 0) {
    return UCS_ERR_BUSY;
  }

  uct_pending_req_queue_push(&iface->super.pending_q, req);
  UCT_TL_EP_STAT_PEND(&ep->super);
  return UCS_OK;
}

ucs_status_t uct_ptl_am_ep_check(uct_ep_h tl_ep, unsigned flags,
                                 uct_completion_t *comp)
{
  ucs_status_t rc;
  uct_iov_t    iov;

  UCT_EP_KEEPALIVE_CHECK_PARAM(flags, comp);

  iov.buffer = NULL;
  iov.length = 0;
  // Send 0 length message.
  rc = uct_ptl_am_ep_put_zcopy(tl_ep, &iov, 1, 0, 0, comp);
  if (rc != UCS_OK) {
    // FIXME: if no resource, add to pending requests
    return ((rc == UCS_ERR_NO_RESOURCE) || (rc == UCS_INPROGRESS)) ? UCS_OK :
                                                                     rc;
  }

  return rc;
}

UCS_CLASS_INIT_FUNC(uct_ptl_am_ep_t, const uct_ep_params_t *params)
{
  uct_ptl_am_iface_t *iface = ucs_derived_of(params->iface, uct_ptl_am_iface_t);
  uct_ptl_am_iface_addr_t *addr = (uct_ptl_am_iface_addr_t *)params->iface_addr;

  UCS_CLASS_CALL_SUPER_INIT(uct_ptl_ep_t, &iface->super, params);

  self->am_mmd           = &iface->am_mmd;
  self->rma_mmd          = iface->rma_mmd;
  self->iface_addr       = *addr;
  self->super.conn_state = UCT_PTL_EP_CONN_CONNECTED;

  return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ptl_am_ep_t)
{
  uct_ep_pending_purge(&self->super.super.super,
                       ucs_empty_function_do_assert_void, NULL);
  //TODO: finish all pending operations that are not on the pending list.
  ucs_debug("destroy ptl ep %p", self);
  return;
}

UCS_CLASS_DEFINE(uct_ptl_am_ep_t, uct_ptl_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_ptl_am_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_ptl_am_ep_t, uct_ep_t);
