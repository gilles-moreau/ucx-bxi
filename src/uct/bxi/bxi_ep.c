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
  op->get.unpack_cb(op->get.unpack_arg, resp, op->length);

  uct_invoke_completion(op->user_comp, UCS_OK);
  ucs_mpool_put(op);
}

void uct_bxi_ep_get_bcopy_handler_no_completion(uct_bxi_iface_send_op_t *op,
                                                const void              *resp)
{
  op->get.unpack_cb(op->get.unpack_arg, resp, op->length);
  ucs_mpool_put(op);
}

static void uct_bxi_get_rndv_handler(uct_bxi_iface_send_op_t *op,
                                     const void              *resp)
{
  /* First, invoke tag-related callback. */
  op->rndv.ctx->completed_cb(op->rndv.ctx, op->rndv.tag, 0, op->length, NULL,
                             UCS_OK);

  /* Then, we may push OP back to the memory pool. */
  ucs_mpool_put_inline(op);
}

static void uct_bxi_send_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                         const void              *resp)
{
  uct_invoke_completion(op->user_comp, UCS_OK);
  ucs_mpool_put_inline(op);
}

static void uct_bxi_send_rndv_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                              const void              *resp)
{
  uct_invoke_completion(op->user_comp, UCS_OK);
  ucs_mpool_put_inline(&op->rndv.block->elem);
  ucs_mpool_put_inline(op);
}

static void
uct_bxi_send_rndv_op_handler_no_completion(uct_bxi_iface_send_op_t *op,
                                           const void              *resp)
{
  ucs_mpool_put_inline(&op->rndv.block->elem);
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

  /* First, get OP while setting appropriate completion callback */
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
    /* For zcopy call, operation is always in progress. */
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

  /* First, get OP while setting appropriate completion callback */
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
                               remote_addr, op));

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
    //FIXME: There are currently no easy way to pass the operation context
    //       through the API. It is copied in the buffer during the
    //       packing callback. Data is located after the OP context.
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

  /* First, get OP while setting appropriate completion callback */
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

static inline size_t uct_bxi_pack_rndv(uct_bxi_iface_t *iface, void *src,
                                       uint64_t remote_addr, size_t length,
                                       const void *header,
                                       unsigned    header_length)
{
  size_t              len = 0;
  uct_bxi_hdr_rndv_t *hdr = src;

  hdr->pti            = iface->rx.rma.pti;
  hdr->remote_addr    = remote_addr;
  hdr->length         = length;
  hdr->header_length  = header_length;
  len                += sizeof(*hdr);

  memcpy(hdr + 1, header, header_length);

  return len + header_length;
}

ucs_status_ptr_t
uct_bxi_ep_tag_rndv_zcopy(uct_ep_h tl_ep, uct_tag_t tag, const void *header,
                          unsigned header_length, const uct_iov_t *iov,
                          size_t iovcnt, unsigned flags, uct_completion_t *comp)
{
  ucs_status_t     status;
  ptl_iovec_t     *ptl_iov;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t    *op;
  uct_bxi_recv_block_params_t params;
  uct_bxi_recv_block_t       *block;
  ptl_hdr_data_t              hdr = 0;

  UCT_BXI_CHECK_EP_PTR(ep);
  UCT_BXI_CHECK_IOV_SIZE_PTR(iovcnt, (unsigned long)iface->config.max_iovecs,
                             "uct_bxi_ep_get_zcopy");

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  /* First, allocate a TAG block from the memory pool. */
  UCT_BXI_IFACE_GET_RX_TAG_DESC_PTR(iface, &iface->tm.recv_block_mp, block,
                                    status = UCS_ERR_NO_RESOURCE;
                                    goto err);

  params.start = ptl_iov->iov_base;
  params.size  = ptl_iov->iov_len;
  /* ME match bits is the operation sequence number prefixed with a specific 
   * rendez-vous bit sequence. */
  params.match   = UCT_BXI_RNDV_GET_TAG(iface->tx.mem_desc->sn + 1);
  params.cth     = PTL_INVALID_HANDLE;
  params.ign     = 0;
  params.options = PTL_ME_OP_GET | PTL_ME_EVENT_LINK_DISABLE |
                   PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_MAY_ALIGN |
                   PTL_ME_IS_ACCESSIBLE | PTL_ME_USE_ONCE;

  /* Then, post the memory entry to the priority list. Target will execute 
   * a GET operation on this */
  status = uct_bxi_recv_block_activate(block, &params);
  if (status != UCS_OK) {
    goto err;
  }

  /* Now, allocate a send descriptor to pack rendez-vous metadata. */
  UCT_BXI_IFACE_GET_TX_TAG_DESC_ERR(iface, &iface->tx.send_desc_mp, op, comp,
                                    uct_iov_total_length(iov, iovcnt),
                                    status = UCS_ERR_NO_RESOURCE;
                                    goto err_release_block;);

  op->length = uct_bxi_pack_rndv(iface, op + 1, (uint64_t)ptl_iov->iov_base,
                                 ptl_iov->iov_len, header, header_length);

  UCT_BXI_HDR_SET(hdr, iface->tx.mem_desc->sn + 1, UCT_BXI_TAG_PROT_RNDV_HW);
  //TODO: implement triggered operation
  status = uct_ptl_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               op->length, PTL_CT_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.tag, tag, 0, op, hdr));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut rndv zcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op_sn(iface->tx.mem_desc, op);

  return (ucs_status_ptr_t)op;

err_release_block:
  uct_bxi_recv_block_deactivate(block);
  ucs_mpool_put_inline(block);
err:
  return UCS_STATUS_PTR(status);
}

ucs_status_t uct_bxi_ep_tag_rndv_cancel(uct_ep_h tl_ep, void *tl_op)
{
  uct_bxi_iface_send_op_t *op = (uct_bxi_iface_send_op_t *)tl_op;

  uct_bxi_recv_block_deactivate(op->rndv.block);

  uct_bxi_send_rndv_op_handler_no_completion(op, NULL);

  return UCS_OK;
}

ucs_status_t uct_bxi_ep_tag_rndv_zcopy_get(uct_bxi_ep_t *ep, uct_tag_t tag,
                                           uct_bxi_recv_block_t *block)
{
  ucs_status_t     status;
  uct_bxi_iface_t *iface =
          ucs_derived_of(ep->super.super.iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, NULL,
                               uct_bxi_get_rndv_handler, block->size);

  /* Associate iface and the tag context of the receive block so that 
   * the completion callback may be called. This enables the block 
   * to be released by caller. */
  op->rndv.ctx   = block->ctx;
  op->rndv.iface = iface;
  op->length     = block->size;

  //NOTE: block length should have been set by caller, during event
  //      handling.
  //NOTE: remote address is the remote offset here since the operation
  //      will match the specific GET ME posted by initiator.
  status =
          uct_ptl_wrap(PtlGet(iface->tx.mem_desc->mdh, (ptl_size_t)block->start,
                              block->size, ep->dev_addr.pid, ep->iface_addr.tag,
                              UCT_BXI_RNDV_GET_TAG(tag), 0, op));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlGet rndv zcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op_sn(iface->tx.mem_desc, op);

  return status;
}

static ucs_status_t uct_bxi_ep_tag_rndv_get_progress(uct_pending_req_t *uct_req)
{
  ucs_status_t           status;
  uct_bxi_pending_req_t *req = ucs_derived_of(uct_req, uct_bxi_pending_req_t);

  status = uct_bxi_ep_tag_rndv_zcopy_get(req->ep, req->tag, req->block);
  if (status == UCS_OK) {
    ucs_mpool_put(req);
  } else {
    ucs_assert(status == UCS_ERR_NO_RESOURCE);
  }

  return status;
}

ucs_status_t uct_bxi_ep_pending_get_add(uct_bxi_ep_t *ep, uct_tag_t tag,
                                        uct_bxi_recv_block_t *block)
{
  uct_bxi_iface_t *iface =
          ucs_derived_of(ep->super.super.iface, uct_bxi_iface_t);
  uct_bxi_pending_req_t *req;
  ucs_status_t           status;

  req = ucs_mpool_get(&iface->tx.pending_mp);
  if (req == NULL) {
    return UCS_ERR_NO_MEMORY;
  }

  req->ep         = ep;
  req->tag        = tag;
  req->block      = block;
  req->super.func = uct_bxi_ep_tag_rndv_get_progress;
  status          = uct_bxi_ep_pending_add(&ep->super.super, &req->super, 0);

  ucs_assert_always(status == UCS_OK);

  return UCS_OK;
}

ucs_status_t uct_bxi_ep_tag_rndv_request(uct_ep_h tl_ep, uct_tag_t tag,
                                         const void *header,
                                         unsigned header_length, unsigned flags)
{
  ucs_status_t     status;
  ptl_hdr_data_t   hdr   = 0;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_LENGTH(header_length, 0, iface->config.seg_size,
                   "tag_rndv_request");

  /* Allocate a send descriptor to pack rendez-vous metadata. */
  UCT_BXI_IFACE_GET_TX_TAG_DESC_ERR(iface, &iface->tx.send_desc_mp, op, NULL,
                                    header_length, status = UCS_ERR_NO_RESOURCE;
                                    goto err);

  memcpy(op + 1, header, header_length);

  //TODO: implement triggered operation
  UCT_BXI_HDR_SET(hdr, 0, UCT_BXI_TAG_PROT_RNDV_SW);
  status = uct_ptl_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               header_length, PTL_CT_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.tag, tag, 0, op, hdr));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut rndv request return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op_sn(iface->tx.mem_desc, op);

err:
  return status;
}

ucs_status_t uct_bxi_iface_tag_recv_zcopy(uct_iface_h tl_iface, uct_tag_t tag,
                                          uct_tag_t        tag_mask,
                                          const uct_iov_t *iov, size_t iovcnt,
                                          uct_tag_context_t *ctx)
{
  ucs_status_t                status;
  ptl_iovec_t                *ptl_iov;
  uct_bxi_iface_t            *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);
  ptl_handle_ct_t             cth   = PTL_CT_NONE;
  unsigned                    ct_flags = 0;
  uct_bxi_op_ctx_t           *op_ctx;
  uct_bxi_recv_block_t       *block;
  uct_bxi_recv_block_params_t params;

  UCT_PTL_CHECK_TAG(iface);
  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_iface_tag_recv_zcopy");

  status = uct_bxi_iface_tag_add_to_hash(iface, iov[0].buffer);
  if (status != UCS_OK) {
    goto err;
  }

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  if (ctx->oop_ctx != NULL && ctx->flags == UCT_TAG_OFFLOAD_OPERATION) {
    /* User specified a context to offload operations. */
    op_ctx = ucs_derived_of(ctx->oop_ctx, uct_bxi_op_ctx_t);
    cth    = op_ctx->cth;
    op_ctx->threshold++;
    ct_flags = PTL_ME_EVENT_CT_COMM | PTL_ME_EVENT_CT_OVERFLOW;
    ucs_debug("BXI: recv oop. oop_ctx=%p, thresh=%ld", op_ctx,
              op_ctx->threshold);
  }

  /* First, allocate a TAG block from the memory pool. */
  UCT_BXI_IFACE_GET_RX_TAG_DESC_PTR(iface, &iface->tm.recv_block_mp, block,
                                    status = UCS_ERR_NO_RESOURCE;
                                    goto err_remove_hash);

  params.start   = ptl_iov->iov_base;
  params.size    = ptl_iov->iov_len;
  params.match   = tag;
  params.cth     = cth;
  params.ign     = 0;
  params.options = PTL_ME_OP_PUT | PTL_ME_USE_ONCE | PTL_ME_EVENT_OVER_DISABLE |
                   PTL_ME_EVENT_LINK_DISABLE | PTL_ME_EVENT_UNLINK_DISABLE |
                   ct_flags;

  /* Then, post the memory entry. The Portals Priority list has already been set 
   * during memory initialization. */
  status = uct_bxi_recv_block_activate(block, &params);
  if (status != UCS_OK) {
    goto err_release_block;
  }

  *(uct_bxi_recv_block_t **)ctx->priv = block;

  return status;

err_release_block:
  ucs_mpool_put_inline(block);
err_remove_hash:
  uct_bxi_iface_tag_del_from_hash(iface, ptl_iov->iov_base);
err:
  return status;
}

ucs_status_t uct_bxi_iface_tag_recv_cancel(uct_iface_h        tl_iface,
                                           uct_tag_context_t *ctx, int force)
{
  uct_bxi_recv_block_t *block = *(uct_bxi_recv_block_t **)ctx->priv;
  uct_bxi_iface_t      *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);

  //NOTE: there is no error checking here because the ME might have been
  //unlinked already during the receive call.
  //FIXME: actually no. Recheck
  uct_bxi_recv_block_deactivate(block);

  if (force) {
    uct_bxi_iface_tag_del_from_hash(iface, block->start);
    ucs_mpool_put_inline(block);
  }

  return UCS_OK;
}

UCS_CLASS_INIT_FUNC(uct_bxi_ep_t, const uct_ep_params_t *params)
{
  ucs_status_t     status;
  uct_bxi_iface_t *iface = ucs_derived_of(params->iface, uct_bxi_iface_t);

  UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super);

  self->dev_addr   = *(uct_bxi_device_addr_t *)params->dev_addr;
  self->iface_addr = *(uct_bxi_iface_addr_t *)params->iface_addr;
  self->conn_state = UCT_BXI_EP_CONN_CONNECTED;

  status = uct_bxi_iface_add_ep(iface, self);
  ucs_assert_always(status == UCS_OK);

  return status;
}

static UCS_CLASS_CLEANUP_FUNC(uct_bxi_ep_t)
{
  uct_ep_pending_purge(&self->super.super, ucs_empty_function_do_assert_void,
                       NULL);

  //TODO: finish all pending operations that are not on the pending list.
  return;
}

UCS_CLASS_DEFINE(uct_bxi_ep_t, uct_ptl_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_bxi_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_bxi_ep_t, uct_ep_t);
