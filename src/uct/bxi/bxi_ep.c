#include "bxi_ep.h"
#include "bxi_iface.h"
#include "bxi_log.h"
#include "bxi_rxq.h"
#include "ptl_types.h"

#include <sys/types.h>
#include <time.h>
#include <uct/base/uct_log.h>

void uct_bxi_ep_get_bcopy_handler(uct_bxi_iface_send_op_t *op, const void *resp)
{
  op->unpack_cb(op->unpack_arg, resp, op->length);

  uct_invoke_completion(op->user_comp, UCS_OK);
  ucs_mpool_put(op);
}

void uct_bxi_ep_get_bcopy_handler_no_completion(uct_bxi_iface_send_op_t *op,
                                                const void              *resp)
{
  op->unpack_cb(op->unpack_arg, resp, op->length);
  ucs_mpool_put(op);
}

static void uct_bxi_send_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                         const void              *resp)
{
  uct_invoke_completion(op->user_comp, UCS_OK);
  ucs_mpool_put_inline(op);
}

ucs_status_t uct_bxi_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t hdr,
                                 const void *buffer, unsigned length)
{
  return UCS_ERR_UNSUPPORTED;
}

ucs_status_t uct_bxi_ep_am_short_iov(uct_ep_h tl_ep, uint8_t id,
                                     const uct_iov_t *iov, size_t iovcnt)
{
  return UCS_ERR_UNSUPPORTED;
}

ssize_t uct_bxi_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id,
                            uct_pack_callback_t pack, void *arg, unsigned flags)
{
  ucs_status_t     status = UCS_OK;
  uct_bxi_ep_t    *ep     = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface  = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;
  ptl_size_t               size;

  UCT_CHECK_AM_ID(id);
  UCT_BXI_CHECK_EP(ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_AM_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, pack,
                                     arg, &size);
  if (size < 0) {
    goto err;
  }

  status = uct_ptl_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               size, PTL_CT_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.am, id, 0, op, 0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op_sn(iface->tx.mem_desc, op);

  UCT_TL_EP_STAT_OP(&ep->super, AM, BCOPY, length);
  uct_bxi_iface_trace_am(ucs_derived_of(tl_ep->iface, uct_bxi_iface_t),
                         UCT_AM_TRACE_TYPE_SEND, id, op + 1, size);
err:
  return size;
}

ucs_status_t uct_bxi_ep_am_zcopy(uct_ep_h tl_ep, uint8_t id, const void *header,
                                 unsigned header_length, const uct_iov_t *iov,
                                 size_t iovcnt, unsigned flags,
                                 uct_completion_t *comp)
{
  return UCS_ERR_UNSUPPORTED;
}

ucs_status_t uct_bxi_ep_put_short(uct_ep_h tl_ep, const void *buffer,
                                  unsigned length, uint64_t remote_addr,
                                  uct_rkey_t rkey)
{
  ucs_status_t             status;
  uct_bxi_iface_send_op_t *op;
  uct_bxi_ep_t            *ep = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface      = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);

  UCT_CHECK_LENGTH(length, 0, iface->config.max_inline, "put_short");
  UCT_BXI_CHECK_EP(ep);

  UCT_BXI_IFACE_GET_TX_OP(iface, &iface->tx.send_op_mp, op, length);

  status = uct_ptl_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)buffer,
                               length, PTL_CT_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.rma, 0, remote_addr, op, 0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut short return %d", status);
  }

  /* Append operation to completion queue. */
  uct_bxi_ep_add_send_op_sn(iface->tx.mem_desc, op);
  UCT_TL_EP_STAT_OP(&ep->super, PUT, SHORT, length);
  uct_bxi_log_put(iface);

err:
  return status;
}

ssize_t uct_bxi_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                             void *arg, uint64_t remote_addr, uct_rkey_t rkey)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;
  ssize_t                  size = 0;

  UCT_BXI_CHECK_EP(ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_PUT_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op,
                                      pack_cb, arg, size);
  if (size < 0) {
    goto err;
  }

  status = uct_ptl_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               size, PTL_CT_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.rma, 0, remote_addr, op, 0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op_sn(iface->tx.mem_desc, op);

  UCT_TL_EP_STAT_OP(&ep->super, PUT, BCOPY, size);
  uct_bxi_log_put(iface);

err:
  return size;
}

ucs_status_t uct_bxi_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                  size_t iovcnt, uint64_t remote_addr,
                                  uct_rkey_t rkey, uct_completion_t *comp)
{
  ucs_status_t     status;
  size_t           iov_size;
  ptl_iovec_t     *ptl_iov;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_ep_put_zcopy");

  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, comp,
                               uct_bxi_send_comp_op_handler,
                               uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov  = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  iov_size = uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);
  UCT_SKIP_ZERO_LENGTH(iov_size);

  status = uct_ptl_wrap(PtlPut(iface->tx.mem_desc->mdh,
                               (ptl_size_t)ptl_iov->iov_base, ptl_iov->iov_len,
                               PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.rma, 0, remote_addr, op, 0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }

  /* Append operation to completion queue. */
  uct_bxi_ep_add_send_op_sn(iface->tx.mem_desc, op);
  UCT_TL_EP_STAT_OP(&ep->super.super, PUT, ZCOPY,
                    uct_iov_total_length(iov, iovcnt));
  uct_bxi_log_put(iface);

err:
  return status;
}

ucs_status_t uct_bxi_ep_get_bcopy(uct_ep_h              tl_ep,
                                  uct_unpack_callback_t unpack_cb, void *arg,
                                  size_t length, uint64_t remote_addr,
                                  uct_rkey_t rkey, uct_completion_t *comp)
{
  ucs_status_t             status;
  uct_bxi_iface_send_op_t *op;
  uct_bxi_ep_t            *ep = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface      = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_GET_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op,
                                      unpack_cb, comp, arg, length);
  status = uct_ptl_wrap(PtlGet(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               length, ep->dev_addr.pid, ep->iface_addr.rma, 0,
                               remote_addr, NULL));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlGet bcopy return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }
  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op_sn(iface->tx.mem_desc, op);

  UCT_TL_EP_STAT_OP(&ep->super, GET, BCOPY, length);
  uct_bxi_log_put(iface);

err:
  return status;
}

ucs_status_t uct_bxi_ep_get_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                  size_t iovcnt, uint64_t remote_addr,
                                  uct_rkey_t rkey, uct_completion_t *comp)
{
  ucs_status_t     status;
  size_t           iov_size;
  ptl_iovec_t     *ptl_iov;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_ep_get_zcopy");

  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, comp,
                               uct_bxi_send_comp_op_handler,
                               uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov  = ucs_alloca(iovcnt * sizeof(ptl_size_t));
  iov_size = uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);
  UCT_SKIP_ZERO_LENGTH(iov_size);

  status = uct_ptl_wrap(PtlGet(iface->tx.mem_desc->mdh,
                               (ptl_size_t)ptl_iov->iov_base, ptl_iov->iov_len,
                               ep->dev_addr.pid, ep->iface_addr.rma, 0,
                               remote_addr, NULL));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlGet bcopy return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }
  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op_sn(iface->tx.mem_desc, op);

  UCT_TL_EP_STAT_OP(&ep->super, GET, ZCOPY, length);
  uct_bxi_log_put(iface);

err:
  return status;
}

ucs_status_t uct_bxi_ep_tag_eager_short(uct_ep_h ep, uct_tag_t tag,
                                        const void *data, size_t length)
{
  return UCS_ERR_NOT_IMPLEMENTED;
}

ssize_t uct_bxi_ep_tag_eager_bcopy(uct_ep_h tl_ep, uct_tag_t tag, uint64_t imm,
                                   uct_pack_callback_t pack_cb, void *arg,
                                   unsigned flags)
{
  ucs_status_t      status;
  uct_bxi_ep_t     *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t  *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  ssize_t           size  = 0;
  uct_bxi_op_ctx_t *op_ctx;
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_AM_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op,
                                     pack_cb, arg, &size);
  if (size < 0) {
    goto err;
  }

  if (flags & UCT_TAG_OFFLOAD_OPERATION) {
    op_ctx = (uct_bxi_op_ctx_t *)(op + 1);
    ucs_assert(!PtlHandleIsEqual(op_ctx->cth, PTL_INVALID_HANDLE));

    status = uct_ptl_wrap(PtlTriggeredPut(
            iface->tx.mem_desc->mdh,
            (ptl_size_t)UCS_PTR_BYTE_OFFSET(op + 1, sizeof(uct_oop_ctx_h)),
            size, PTL_CT_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.tag, tag, 0,
            op, imm, op_ctx->cth, op_ctx->threshold));
  } else {
    status = uct_ptl_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 size, PTL_CT_ACK_REQ, ep->dev_addr.pid,
                                 ep->iface_addr.tag, tag, 0, op, imm));
  }

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op_sn(iface->tx.mem_desc, op);

  UCT_TL_EP_STAT_OP(&ep->super, TAG, BCOPY, size);
  uct_bxi_log_put(iface);

err:
  return size;
}

ucs_status_t uct_bxi_ep_tag_eager_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                        uint64_t imm, const uct_iov_t *iov,
                                        size_t iovcnt, unsigned flags,
                                        uct_completion_t *comp)
{

  ucs_status_t      status;
  size_t            iov_size;
  ptl_iovec_t      *ptl_iov;
  uct_bxi_ep_t     *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t  *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_op_ctx_t *op_ctx;
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_ep_get_zcopy");

  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, comp,
                               uct_bxi_send_comp_op_handler,
                               uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov  = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  iov_size = uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);
  UCT_SKIP_ZERO_LENGTH(iov_size);

  if (flags & UCT_TAG_OFFLOAD_OPERATION) {
    op_ctx = ucs_derived_of(comp->oop_ctx, uct_bxi_op_ctx_t);
    ucs_assert(!PtlHandleIsEqual(op_ctx->cth, PTL_INVALID_HANDLE));

    status = uct_ptl_wrap(PtlTriggeredPut(
            iface->tx.mem_desc->mdh, (ptl_size_t)ptl_iov->iov_base,
            ptl_iov->iov_len, PTL_CT_ACK_REQ, ep->dev_addr.pid,
            ep->iface_addr.tag, tag, 0, op, imm, op_ctx->cth,
            op_ctx->threshold));
  } else {
    status = uct_ptl_wrap(
            PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)ptl_iov->iov_base,
                   ptl_iov->iov_len, PTL_CT_ACK_REQ, ep->dev_addr.pid,
                   ep->iface_addr.tag, tag, 0, op, imm));
  }
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlGet bcopy return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }
  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op_sn(iface->tx.mem_desc, op);

  UCT_TL_EP_STAT_OP(&ep->super, TAG, ZCOPY, length);
  uct_bxi_log_put(iface);

err:
  return status;
}

static inline size_t uct_bxi_pack_rndv(void *src, uint64_t remote_addr,
                                       size_t length, const void *header,
                                       unsigned header_length)
{
  size_t              len = 0;
  uct_bxi_hdr_rndv_t *hdr = src;

  hdr->remote_addr    = remote_addr;
  hdr->length         = length;
  hdr->header_length  = header_length;
  len                += sizeof(*hdr);

  memcpy(hdr + 1, header, header_length);

  return len + header_length;
}

static inline ucs_status_t
uct_bxi_ep_post_rndv_mem_entry(uct_bxi_iface_t         *iface,
                               uct_bxi_iface_send_op_t *op, ptl_iovec_t *iov,
                               int iovcnt)
{
  ucs_status_t          status;
  uct_bxi_recv_block_t *block;
  ptl_me_t              me;

  UCT_BXI_IFACE_GET_RX_TAG_DESC_PTR(iface, &iface->tm.recv_block_mp, block,
                                    status = UCS_ERR_NO_RESOURCE;
                                    goto err);

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

  rc = uct_ptl_wrap(PtlMEAppend(iface->md->nih, iface->rx.tag.queue->pti, &me,
                                PTL_PRIORITY_LIST, op, &op->tag.meh));
err:
  return status;
}

ucs_status_ptr_t
uct_bxi_ep_tag_rndv_zcopy(uct_ep_h tl_ep, uct_tag_t tag, const void *header,
                          unsigned header_length, const uct_iov_t *iov,
                          size_t iovcnt, unsigned flags, uct_completion_t *comp)
{
  ucs_status_t          rc = UCS_OK;
  size_t                iov_size;
  ptl_iovec_t          *ptl_iov;
  uct_bxi_ep_t         *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t      *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_recv_block_t *block;
  uct_bxi_iface_send_op_t *op;
  ptl_hdr_data_t           hdr = 0;
  ptl_me_t                 me;

  UCT_BXI_CHECK_EP_PTR(ep);
  UCT_BXI_CHECK_IOV_SIZE_PTR(iovcnt, (unsigned long)iface->config.max_iovecs,
                             "uct_bxi_ep_get_zcopy");

  UCT_BXI_IFACE_GET_TX_TAG_DESC_PTR(iface, &iface->tx.send_desc_mp, op, comp,
                                    uct_bxi_send_comp_op_handler,
                                    uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov  = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  iov_size = uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  op->length = uct_bxi_pack_rndv(op + 1, (uint64_t)ptl_iov->iov_base,
                                 ptl_iov->iov_len, header, header_length);

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

ucs_status_t uct_bxi_ep_tag_rndv_cancel(uct_ep_h tl_ep, void *tl_op)
{
  uct_ptl_op_t    *op    = (uct_ptl_op_t *)tl_op;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = uct_ptl_ep_iface(ep, uct_bxi_iface_t);

  if (!PtlHandleIsEqual(op->tag.meh, PTL_INVALID_HANDLE)) {
    uct_ptl_wrap(PtlMEUnlink(op->tag.meh));
    iface->tm.num_get_tags++;
  }

  ucs_debug("PTL: (C) op complete. id=%lu, type=%d", op->seqn, op->type);
  ucs_mpool_put(op);
  return UCS_OK;
}

ucs_status_t uct_bxi_ep_tag_rndv_request(uct_ep_h tl_ep, uct_tag_t tag,
                                         const void *header,
                                         unsigned header_length, unsigned flags)
{
  ucs_status_t     rc    = UCS_OK;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = uct_ptl_ep_iface(ep, uct_bxi_iface_t);
  ptl_hdr_data_t   hdr   = 0;
  uct_ptl_op_t    *op    = NULL;

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

ucs_status_t uct_bxi_iface_tag_recv_zcopy(uct_iface_h tl_iface, uct_tag_t tag,
                                          uct_tag_t        tag_mask,
                                          const uct_iov_t *iov, size_t iovcnt,
                                          uct_tag_context_t *ctx)
{
  ucs_status_t       rc = UCS_OK;
  int                ret;
  ptl_me_t           me;
  uct_bxi_iface_t   *iface    = ucs_derived_of(tl_iface, uct_bxi_iface_t);
  ptl_handle_ct_t    cth      = PTL_CT_NONE;
  unsigned           ct_flags = 0;
  uct_ptl_oop_ctx_t *oop_ctx;
  uct_ptl_op_t      *op;
  static uint32_t    seqn = 0;

  ucs_assert(iov && iovcnt == 1);
  UCT_PTL_CHECK_TAG(iface);

  ret = uct_bxi_iface_tag_add_to_hash(iface, iov[0].buffer);
  if (ret != UCS_OK) {
    return ret;
  }

  if (ctx->oop_ctx != NULL && ctx->flags == UCT_TAG_OFFLOAD_OPERATION) {
    /* User specified a context to offload operations. */
    oop_ctx = ucs_derived_of(ctx->oop_ctx, uct_ptl_oop_ctx_t);
    cth     = oop_ctx->cth;
    oop_ctx->threshold++;
    ct_flags = PTL_ME_EVENT_CT_COMM | PTL_ME_EVENT_CT_OVERFLOW;
    ucs_debug("PTL: recv oop. oop_ctx=%p, thresh=%ld", oop_ctx,
              oop_ctx->threshold);
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
  uct_bxi_iface_tag_del_from_hash(iface, iov[0].buffer);
  return rc;
}

ucs_status_t uct_bxi_iface_tag_recv_cancel(uct_iface_h        tl_iface,
                                           uct_tag_context_t *ctx, int force)
{
  ucs_status_t     rc    = UCS_OK;
  uct_ptl_op_t    *op    = *(uct_ptl_op_t **)ctx->priv;
  uct_bxi_iface_t *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);

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

  if (force) {
    uct_bxi_iface_tag_del_from_hash(iface, op->tag.buffer);
    ucs_mpool_put(op);
  } else {
    // Push it to cancel queue to make it complete if necessary during the
    // progress phase. This is necessary to pass some UCT test...
    ucs_queue_push(&iface->tm.canceled_ops, &op->elem);
  }
err:
  return rc;
}
