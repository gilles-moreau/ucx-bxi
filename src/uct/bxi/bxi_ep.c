#include "bxi_ep.h"
#include "bxi_iface.h"
#include "bxi_log.h"
#include "bxi_rxq.h"

#include <sys/types.h>
#include <time.h>
#include <uct/base/uct_log.h>

ptl_op_t uct_bxi_atomic_op_table[] = {
        [UCT_ATOMIC_OP_ADD] = PTL_SUM,   [UCT_ATOMIC_OP_AND] = PTL_BAND,
        [UCT_ATOMIC_OP_OR] = PTL_BOR,    [UCT_ATOMIC_OP_XOR] = PTL_BXOR,
        [UCT_ATOMIC_OP_SWAP] = PTL_SWAP, [UCT_ATOMIC_OP_CSWAP] = PTL_CSWAP,
};

void uct_bxi_ep_get_bcopy_handler(uct_bxi_iface_send_op_t *op, const void *resp)
{
  op->get.unpack_cb(op->get.unpack_arg, resp, op->length);

  uct_invoke_completion(op->user_comp, UCS_OK);

  ucs_list_del(&op->elem);
  ucs_mpool_put_inline(op);
}

void uct_bxi_ep_get_bcopy_handler_no_completion(uct_bxi_iface_send_op_t *op,
                                                const void              *resp)
{
  op->get.unpack_cb(op->get.unpack_arg, resp, op->length);

  ucs_list_del(&op->elem);
  ucs_mpool_put_inline(op);
}

static void uct_bxi_send_op_no_completion(uct_bxi_iface_send_op_t *op,
                                          const void              *resp)
{
  ucs_list_del(&op->elem);
  ucs_mpool_put_inline(op);
}

static void uct_bxi_send_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                         const void              *resp)
{
  uct_invoke_completion(op->user_comp, UCS_OK);

  ucs_list_del(&op->elem);
  ucs_mpool_put_inline(op);
}

static void uct_bxi_send_rndv_ack_handler(uct_bxi_iface_send_op_t *op,
                                          const void              *resp)
{
  //FIXME: INUSE flags to pass asserts.
  op->flags |= UCT_BXI_IFACE_SEND_OP_FLAG_INUSE;
  /* During ACK, reset handler for next PTL_EVENT_GET. Operation has to 
   * be released when the GET operation from target is completed. */
  op->handler = op->user_comp == NULL ? uct_bxi_send_op_no_completion :
                                        uct_bxi_send_comp_op_handler;
}

static void uct_bxi_ep_flush_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                             const void              *resp)
{
  uct_invoke_completion(op->user_comp, UCS_OK);

  ucs_list_del(&op->elem);
  ucs_mpool_put_inline(op);
}

static void uct_bxi_get_tag_handler(uct_bxi_iface_send_op_t *op,
                                    const void              *resp)
{
  /* First, invoke tag-related callback. */
  op->rndv.ctx->completed_cb(op->rndv.ctx, op->rndv.tag, 0, op->length, NULL,
                             UCS_OK);

  /* Then, we may push OP back to the memory pool. */
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
  UCT_BXI_CHECK_IFACE_RES(iface);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_AM_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                     pack, arg, &size);
  if (size < 0) {
    goto err;
  }

  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               size, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.am, id, 0, op, 0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut return %d", status);
  }

  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, AM, BCOPY, length);
  uct_bxi_iface_trace_am(ucs_derived_of(tl_ep->iface, uct_bxi_iface_t),
                         UCT_AM_TRACE_TYPE_SEND, id, op + 1, size);
err:
  return size;
}

//NOTE: zcopy can be useful for scatter/gather data but as it is considered as
//      eager, its size is limited by the seg_size that can be used in receiver's
//      bounce buffer.
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
  UCT_BXI_CHECK_IFACE_RES(iface);

  UCT_BXI_IFACE_GET_TX_OP(iface, &iface->tx.send_op_mp, op, ep, length);

  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)buffer,
                               length, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.rma, 0, remote_addr, op, 0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut short return %d", status);
  }

  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);
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
  UCT_BXI_CHECK_IFACE_RES(iface);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_PUT_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                      pack_cb, arg, size);
  if (size < 0) {
    goto err;
  }

  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               size, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.rma, 0, remote_addr, op, 0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  }

  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);

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
  UCT_BXI_CHECK_IFACE_RES(iface);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_comp_op_handler,
                               uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov  = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  iov_size = uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);
  UCT_SKIP_ZERO_LENGTH(iov_size);

  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh,
                               (ptl_size_t)ptl_iov->iov_base, ptl_iov->iov_len,
                               PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.rma, 0, remote_addr, op, 0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  } else {
    /* For zcopy call, operation is always in progress. */
    status = UCS_INPROGRESS;
  }

  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);
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

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_GET_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                      unpack_cb, comp, arg, length);

  status = uct_bxi_wrap(PtlGet(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               length, ep->dev_addr.pid, ep->iface_addr.rma, 0,
                               remote_addr, op));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlGet bcopy return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }
  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);

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
  UCT_BXI_CHECK_IFACE_RES(iface);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_comp_op_handler,
                               uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov  = ucs_alloca(iovcnt * sizeof(ptl_size_t));
  iov_size = uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);
  UCT_SKIP_ZERO_LENGTH(iov_size);

  status = uct_bxi_wrap(PtlGet(iface->tx.mem_desc->mdh,
                               (ptl_size_t)ptl_iov->iov_base, ptl_iov->iov_len,
                               ep->dev_addr.pid, ep->iface_addr.rma, 0,
                               remote_addr, op));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlGet bcopy return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }
  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);

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

static ucs_status_t uct_bxi_ep_op_ctx_multiple(uct_iface_h        tl_iface,
                                               ucs_list_link_t   *op_head,
                                               uct_bxi_op_ctx_t **op_ctx_p)
{
  ucs_status_t      status;
  uct_bxi_op_ctx_t *op_ctx;
  uct_bxi_op_ctx_t *tmp;

  status = uct_bxi_iface_tag_create_op_ctx(tl_iface, (uct_op_ctx_h *)&op_ctx);
  if (status != UCS_OK) {
    return status;
  }

  ucs_list_for_each (tmp, op_head, super.elem) {
    status = uct_bxi_wrap(PtlTriggeredCTInc(op_ctx->cth, (ptl_ct_event_t){1, 0},
                                            tmp->cth, tmp->threshold));
    if (status != UCS_OK) {
      ucs_fatal("BXI: failed setting trig inc.");
    }
    op_ctx->threshold++;
  }

  *op_ctx_p = op_ctx;

  return status;
}

ssize_t uct_bxi_ep_tag_eager_bcopy(uct_ep_h tl_ep, uct_tag_t tag, uint64_t imm,
                                   uct_pack_callback_t pack_cb, void *arg,
                                   unsigned flags)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  ssize_t          size  = 0;
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_AM_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                     pack_cb, arg, &size);
  if (size < 0) {
    goto err;
  }

  if (ucs_unlikely(flags & UCT_TAG_OFFLOAD_OPERATION)) {
    ucs_error("BXI: triggered operation with bcopy not implemented.");
    return UCS_ERR_NOT_IMPLEMENTED;
  } else {
    status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 size, PTL_ACK_REQ, ep->dev_addr.pid,
                                 ep->iface_addr.tag, tag, 0, op, imm));
  }

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  }

  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, TAG, BCOPY, size);
  uct_bxi_log_put(iface);

err:
  return size;
}

//NOTE: zcopy can be useful for scatter/gather data but as it is considered as
//      eager, its size is limited by the seg_size that can be used in receiver's
//      bounce buffer.
ucs_status_t uct_bxi_ep_tag_eager_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                        uint64_t imm, const uct_iov_t *iov,
                                        size_t iovcnt, unsigned flags,
                                        uct_completion_t *comp)
{

  ucs_status_t      status;
  ptl_iovec_t      *ptl_iov;
  uct_bxi_ep_t     *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t  *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_op_ctx_t *op_ctx;
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_ep_get_zcopy");
  UCT_BXI_CHECK_IFACE_RES(iface);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_TAG_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                                   uct_bxi_send_comp_op_handler,
                                   uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  if (ucs_unlikely(flags & UCT_TAG_OFFLOAD_OPERATION)) {
    if (ucs_list_length(&comp->op_head) > 1) {
      status =
              uct_bxi_ep_op_ctx_multiple(tl_ep->iface, &comp->op_head, &op_ctx);
      if (status != UCS_OK) {
        goto err;
      }
    } else {
      op_ctx = ucs_list_extract_head(&comp->op_head, uct_bxi_op_ctx_t,
                                     super.elem);
    }
    ucs_assert(!PtlHandleIsEqual(op_ctx->cth, PTL_INVALID_HANDLE));

    status = uct_bxi_wrap(PtlTriggeredPut(
            iface->tx.mem_desc->mdh, (ptl_size_t)ptl_iov->iov_base,
            ptl_iov->iov_len, PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.tag,
            tag, 0, op, imm, op_ctx->cth, op_ctx->threshold));
  } else {
    status = uct_bxi_wrap(
            PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)ptl_iov->iov_base,
                   ptl_iov->iov_len, PTL_ACK_REQ, ep->dev_addr.pid,
                   ep->iface_addr.tag, tag, 0, op, imm));
  }
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlGet bcopy return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }
  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, TAG, ZCOPY, length);
  uct_bxi_log_put(iface);

err:
  return status;
}

static inline size_t uct_bxi_pack_rndv(uct_bxi_iface_t *iface, void *src,
                                       unsigned int pti, uint64_t remote_addr,
                                       size_t length, const void *header,
                                       unsigned header_length)
{
  size_t              len = 0;
  uct_bxi_hdr_rndv_t *hdr = src;

  hdr->pti            = pti;
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
  ucs_status_t      status;
  ptl_iovec_t      *ptl_iov;
  uct_bxi_ep_t     *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t  *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_op_ctx_t *op_ctx;
  uct_bxi_iface_send_op_t    *op;
  uct_bxi_recv_block_params_t params;
  uct_bxi_recv_block_t       *block;
  ptl_hdr_data_t              hdr = 0;

  UCT_BXI_CHECK_EP_PTR(ep);
  UCT_BXI_CHECK_IOV_SIZE_PTR(iovcnt, (unsigned long)iface->config.max_iovecs,
                             "uct_bxi_ep_get_zcopy");
  UCT_BXI_CHECK_IFACE_RES_PTR(iface);

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  /* First, allocate a TAG block from the memory pool. */
  //TODO: rename macro
  UCT_BXI_IFACE_GET_RX_TAG_DESC_PTR(iface, &iface->tm.recv_block_mp, block,
                                    status = UCS_ERR_NO_RESOURCE;
                                    goto err);

  params.start = ptl_iov->iov_base;
  params.size  = ptl_iov->iov_len;
  /* ME match bits is the operation sequence number prefixed with a specific 
   * rendez-vous bit sequence. */
  params.match   = flags & UCT_TAG_OFFLOAD_OPERATION ?
                           tag :
                           UCT_BXI_RNDV_GET_TAG(iface->tx.mem_desc->sn + 1);
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
  UCT_BXI_IFACE_GET_TX_TAG_DESC_ERR(iface, &iface->tx.send_desc_mp, op, ep,
                                    comp, uct_bxi_send_rndv_ack_handler,
                                    status = UCS_ERR_NO_RESOURCE;
                                    goto err_release_block;);

  /* Attach operation to block and vice versa so they can be both released, 
   * either on completion or if the operation is canceled. */
  block->op      = op;
  op->rndv.block = block;

  op->length = uct_bxi_pack_rndv(
          iface, op + 1, uct_bxi_rxq_get_addr(iface->rx.tag.q),
          (uint64_t)ptl_iov->iov_base, ptl_iov->iov_len, header, header_length);

  UCT_BXI_HDR_SET(hdr, iface->tx.mem_desc->sn + 1, UCT_BXI_TAG_PROT_RNDV_HW);

  if (ucs_unlikely(flags & UCT_TAG_OFFLOAD_OPERATION)) {
    if (ucs_list_length(&comp->op_head) > 1) {
      status =
              uct_bxi_ep_op_ctx_multiple(tl_ep->iface, &comp->op_head, &op_ctx);
      if (status != UCS_OK) {
        goto err;
      }
    } else {
      op_ctx = ucs_list_extract_head(&comp->op_head, uct_bxi_op_ctx_t,
                                     super.elem);
    }
    ucs_assert(!PtlHandleIsEqual(op_ctx->cth, PTL_INVALID_HANDLE));

    status = uct_bxi_wrap(PtlTriggeredPut(
            iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1), op->length,
            PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.tag, tag, 0, op, hdr,
            op_ctx->cth, op_ctx->threshold));
  } else {
    status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 op->length, PTL_ACK_REQ, ep->dev_addr.pid,
                                 ep->iface_addr.tag, tag, 0, op, hdr));
  }
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut rndv zcopy return %d", status);
  }

  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);

  return (ucs_status_ptr_t)op;

err_release_block:
  uct_bxi_recv_block_deactivate(block);
  uct_bxi_recv_block_release(block);
err:
  return UCS_STATUS_PTR(status);
}

ucs_status_t uct_bxi_ep_tag_rndv_cancel(uct_ep_h tl_ep, void *tl_op)
{
  uct_bxi_iface_send_op_t *op = (uct_bxi_iface_send_op_t *)tl_op;

  /* Deactivate block and release it to memory pool. */
  uct_bxi_recv_block_deactivate(op->rndv.block);
  uct_bxi_recv_block_release(op->rndv.block);

  op->flags &= ~UCT_BXI_IFACE_SEND_OP_FLAG_INUSE;
  uct_bxi_send_op_no_completion(op, NULL);

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
  UCT_BXI_CHECK_IFACE_RES(iface);

  //NOTE: rndv_request cannot be offloaded since the rest of the protocol has
  //      to be done in software. This is the case with generic datatype, very
  //      large message or multiple iov since current hardwares do not support it.
  ucs_assert(!(flags & UCT_TAG_OFFLOAD_OPERATION));

  /* Allocate a send descriptor to pack rendez-vous metadata. */
  UCT_BXI_IFACE_GET_TX_TAG_DESC_ERR(iface, &iface->tx.send_desc_mp, op, ep,
                                    NULL, uct_bxi_send_op_no_completion,
                                    status = UCS_ERR_NO_RESOURCE;
                                    goto err);

  memcpy(op + 1, header, header_length);

  UCT_BXI_HDR_SET(hdr, 0, UCT_BXI_TAG_PROT_RNDV_SW);
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               header_length, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.tag, tag, 0, op, hdr));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut rndv request return %d", status);
  }

  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);

err:
  return status;
}

static UCS_F_ALWAYS_INLINE ucs_status_t uct_bxi_offload_tag_get(
        uct_bxi_ep_t *ep, uct_bxi_iface_t *iface, uct_bxi_iface_send_op_t *op,
        uct_tag_t tag, ptl_iovec_t *iov, size_t iovcnt, uint64_t remote_offset,
        uct_completion_t *comp)

{
  ucs_status_t             status;
  uct_bxi_op_ctx_t        *op_ctx;
  uct_bxi_mem_desc_param_t mem_desc_param;

  //NOTE: for now, get tag is only supported to perform the get
  //      operation within the rendez-vous protocol. As a consequence,
  //      it will only depend on the operation context from the associated
  //      receive.
  ucs_assert((ucs_list_length(&comp->op_head) == 1));

  /* Retrieve operation context. */
  op_ctx = ucs_list_extract_head(&comp->op_head, uct_bxi_op_ctx_t, super.elem);

  /* Counter must have been allocated and block attached to the 
   * operation handle. */
  ucs_assert(!PtlHandleIsEqual(op_ctx->cth, PTL_INVALID_HANDLE) &&
             (op_ctx->block != NULL));

  /* Buffer and size of the get operation should be the same as the receive 
   * block since they correspond to the same protocol. */
  ucs_assert((op_ctx->block->size == iov->iov_len) &&
             (op_ctx->block->start == iov->iov_base));

  /* Create MD and associate operation context counter for it to be incremented 
   * on operation completion. */
  mem_desc_param.eqh     = iface->tx.eqh;
  mem_desc_param.start   = iov->iov_base;
  mem_desc_param.length  = iov->iov_len;
  mem_desc_param.options = PTL_MD_EVENT_CT_REPLY | PTL_MD_EVENT_SEND_DISABLE;
  mem_desc_param.flags   = UCT_BXI_MEM_DESC_FLAG_ALLOCATE;
  mem_desc_param.cth     = op_ctx->cth;
  status = uct_bxi_md_mem_desc_create(uct_bxi_iface_md(iface), &mem_desc_param,
                                      &op->mem_desc);
  if (status != UCS_OK) {
    return status;
  }

  //NOTE: MD has been created using the base address, so the remote offset is 0.
  status = uct_bxi_wrap(PtlTriggeredGet(
          op->mem_desc->mdh, 0, iov->iov_len, ep->dev_addr.pid,
          ep->iface_addr.tag, tag, 0, op, op_ctx->cth, op_ctx->threshold));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlTriggeredGet request return %d", status);
  }

  /* Increase operation counter threshold. There will be two increments:
   * - one for the RTS operation that will match the ME;
   * - one for the completion of the GET operation. */
  op_ctx->threshold++;
  op->flags    |= UCT_BXI_IFACE_SEND_OP_FLAG_EXCL_MD;
  op->length    = op_ctx->block->size;
  op->rndv.ctx  = op_ctx->block->ctx;
  op->rndv.tag  = op_ctx->block->tag;
  op->handler   = uct_bxi_get_tag_handler; // Reset handler.

  /* Also, attach operation to the block. */
  op_ctx->block->op     = op;
  op_ctx->block->flags |= UCT_BXI_RECV_BLOCK_FLAG_HAS_TRIGOP;

  return status;
}

ucs_status_t uct_bxi_ep_tag_get_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                      const uct_iov_t *iov, size_t iovcnt,
                                      uint64_t remote_offset, unsigned flags,
                                      uct_completion_t *comp)
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
  UCT_BXI_CHECK_IFACE_RES(iface);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_comp_op_handler,
                               uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov  = ucs_alloca(iovcnt * sizeof(ptl_size_t));
  iov_size = uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);
  UCT_SKIP_ZERO_LENGTH(iov_size);

  if (ucs_unlikely(flags & UCT_TAG_OFFLOAD_OPERATION)) {
    status = uct_bxi_offload_tag_get(ep, iface, op, tag, ptl_iov, iov_size,
                                     remote_offset, comp);
  } else {
    status = uct_bxi_wrap(PtlGet(iface->tx.mem_desc->mdh,
                                 (ptl_size_t)ptl_iov->iov_base,
                                 ptl_iov->iov_len, ep->dev_addr.pid,
                                 ep->iface_addr.tag, tag, remote_offset, op));
  }

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlGet bcopy return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }
  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, TAG, GET_ZCOPY, length);
  uct_bxi_log_put(iface);

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
  uct_bxi_op_ctx_t           *op_ctx   = NULL;
  uct_bxi_recv_block_t       *block;
  uct_bxi_recv_block_params_t params;

  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_iface_tag_recv_zcopy");

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  memset(ptl_iov, 0, iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  status = uct_bxi_iface_tag_add_to_hash(iface, ptl_iov->iov_base);
  if (status != UCS_OK) {
    goto err;
  }

  if (ctx->op_ctx != NULL) {
    /* User specified a context to offload operations. */
    op_ctx = ucs_derived_of(ctx->op_ctx, uct_bxi_op_ctx_t);
    cth    = op_ctx->cth;
    op_ctx->threshold++;
    ct_flags = PTL_ME_EVENT_CT_COMM | PTL_ME_EVENT_CT_OVERFLOW;
  }

  /* First, allocate a TAG block from the memory pool. */
  UCT_BXI_IFACE_GET_RX_TAG_DESC_PTR(iface, &iface->tm.recv_block_mp, block,
                                    status = UCS_ERR_EXCEEDS_LIMIT;
                                    goto err_remove_hash);

  /* Attach upper layer context. */
  block->ctx = ctx;

  params.start = ptl_iov->iov_base;
  params.size  = ptl_iov->iov_len;
  params.match = tag;
  params.ign   = ~tag_mask;
  params.cth   = cth;
  //FIXME: Add explanation for OVER_DISABLE
  params.options = PTL_ME_OP_PUT | PTL_ME_USE_ONCE | PTL_ME_EVENT_LINK_DISABLE |
                   PTL_ME_EVENT_UNLINK_DISABLE | ct_flags;

  /* Then, post the memory entry. The Portals Priority list has already been set 
   * during memory initialization. */
  status = uct_bxi_recv_block_activate(block, &params);
  if (status != UCS_OK) {
    goto err_release_block;
  }

  /* Link the receive block which will be used in case of rendez-vous protocol. */
  if (op_ctx != NULL) {
    op_ctx->block = block;
  }

  *(uct_bxi_recv_block_t **)ctx->priv = block;

  return status;

err_release_block:
  uct_bxi_recv_block_release(block);
err_remove_hash:
  uct_bxi_iface_tag_del_from_hash(iface, ptl_iov->iov_base);
err:
  return status;
}

ucs_status_t uct_bxi_iface_tag_recv_cancel(uct_iface_h        tl_iface,
                                           uct_tag_context_t *ctx, int force)
{
  ucs_status_t          status = UCS_OK;
  uct_bxi_recv_block_t *block  = *(uct_bxi_recv_block_t **)ctx->priv;
  uct_bxi_iface_t      *iface  = ucs_derived_of(tl_iface, uct_bxi_iface_t);

  /* In case of offloaded rendez-vous, a GET operation has been attached. 
   * Remove all triggered operations attached to this ME. */
  if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_HAS_TRIGOP) {
    ucs_assert(!PtlHandleIsEqual(block->cth, PTL_CT_NONE));
    status = uct_bxi_wrap(PtlCTCancelTriggered(block->cth));
    if (status != UCS_OK) {
      ucs_warn("BXI: tried to cancel triggered operation attached to block. "
               "block=%p",
               block);
    }
  }

  /* Unlink block. */
  uct_bxi_recv_block_deactivate(block);

  if (force) {
    uct_bxi_iface_tag_del_from_hash(iface, block->start);
    uct_bxi_recv_block_release(block);
  } else {
    //FIXME: due to noforce UCT tests, block need to be cancelled
    //       during polling. Since Unlink does not generate any event, we
    //       are required to maintain a list of cancelled blocks.
    ucs_list_add_head(&iface->rx.tag.cancel, &block->c_elem);
  }

  iface->tm.unexp_hdr_count--;

  return status;
}

ucs_status_t uct_bxi_iface_tag_create_op_ctx(uct_iface_h   tl_iface,
                                             uct_op_ctx_h *op_ctx_p)
{
  ucs_status_t      status;
  uct_bxi_op_ctx_t *op_ctx;
  uct_bxi_iface_t  *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);

  op_ctx = ucs_mpool_get(&iface->tm.op_ctx_mp);
  if (op_ctx == NULL) {
    status = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op_ctx->threshold = 0;
  op_ctx->block     = NULL;

  status = uct_bxi_wrap(PtlCTAlloc(uct_bxi_iface_md(iface)->nih, &op_ctx->cth));
  if (status != UCS_OK) {
    goto err_free_op_ctx;
  }

  *op_ctx_p = (uct_op_ctx_h)op_ctx;

  return status;

err_free_op_ctx:
  ucs_mpool_put(op_ctx);
err:
  return status;
}

void uct_bxi_iface_tag_delete_op_ctx(uct_iface_h  tl_iface,
                                     uct_op_ctx_h tl_op_ctx)
{
  uct_bxi_op_ctx_t *op_ctx = (uct_bxi_op_ctx_t *)tl_op_ctx;

  ucs_assert(!PtlHandleIsEqual(op_ctx->cth, PTL_INVALID_HANDLE));

  uct_bxi_wrap(PtlCTFree(op_ctx->cth));

  ucs_mpool_put(op_ctx);
}

static ucs_status_t
uct_bxi_ep_atomic_post_common(uct_ep_h tl_ep, unsigned opcode, uint64_t value,
                              size_t size, ptl_datatype_t dt,
                              uint64_t remote_addr, uct_rkey_t rkey)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, NULL,
                               uct_bxi_send_comp_op_handler, size);

  /* Store the value since the Atomic call needs an address. */
  op->atomic.value = value;

  status = uct_bxi_wrap(
          PtlAtomic(iface->tx.mem_desc->mdh, (uint64_t)&op->atomic.value, size,
                    PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.rma, 0,
                    remote_addr, op, 0, uct_bxi_atomic_op_table[opcode], dt));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlAtomic request return %d", status);
  }

  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_ATOMIC(&ep->super);

  return status;
}

static ucs_status_t
uct_bxi_ep_atomic_fetch_common(uct_ep_h tl_ep, unsigned opcode, uint64_t value,
                               uint64_t *result, size_t size, ptl_datatype_t dt,
                               uint64_t remote_addr, uct_rkey_t rkey,
                               uct_completion_t *comp)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_comp_op_handler, size);

  /* Store the value since the Atomic call needs an address. */
  op->atomic.value = value;

  status = uct_bxi_wrap(PtlFetchAtomic(
          iface->tx.mem_desc->mdh, (uint64_t)result, iface->tx.mem_desc->mdh,
          (uint64_t)&op->atomic.value, size, ep->dev_addr.pid,
          ep->iface_addr.rma, 0, remote_addr, op, 0,
          uct_bxi_atomic_op_table[opcode], dt));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlAtomic request return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }

  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);
  UCT_TL_EP_STAT_ATOMIC(&ep->super);

  return status;
}

static ucs_status_t
uct_bxi_ep_atomic_cswap_common(uct_ep_h tl_ep, uint64_t compare, uint64_t swap,
                               size_t size, ptl_datatype_t dt,
                               uint64_t remote_addr, uct_rkey_t rkey,
                               uint64_t *result, uct_completion_t *comp)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_comp_op_handler, size);

  /* Store the value since the Atomic call needs an address. */
  op->atomic.value   = swap;
  op->atomic.compare = compare;

  status = uct_bxi_wrap(
          PtlSwap(iface->tx.mem_desc->mdh, (uint64_t)result,
                  iface->tx.mem_desc->mdh, (uint64_t)&op->atomic.value, size,
                  ep->dev_addr.pid, ep->iface_addr.rma, 0, remote_addr, op, 0,
                  &op->atomic.compare, PTL_CSWAP, dt));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlAtomic request return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }

  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);
  UCT_TL_EP_STAT_ATOMIC(&ep->super);

  return status;
}

ucs_status_t uct_bxi_ep_atomic_cswap32(uct_ep_h tl_ep, uint32_t compare,
                                       uint32_t swap, uint64_t remote_addr,
                                       uct_rkey_t rkey, uint32_t *result,
                                       uct_completion_t *comp)
{
  return uct_bxi_ep_atomic_cswap_common(
          tl_ep, (uint64_t)compare, (uint64_t)swap, sizeof(uint32_t),
          PTL_UINT32_T, remote_addr, rkey, (uint64_t *)result, comp);
}

ucs_status_t uct_bxi_ep_atomic32_post(uct_ep_h tl_ep, unsigned opcode,
                                      uint32_t value, uint64_t remote_addr,
                                      uct_rkey_t rkey)
{
  return uct_bxi_ep_atomic_post_common(tl_ep, opcode, value, sizeof(uint32_t),
                                       PTL_UINT32_T, remote_addr, rkey);
}

ucs_status_t uct_bxi_ep_atomic32_fetch(uct_ep_h tl_ep, unsigned opcode,
                                       uint32_t value, uint32_t *result,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp)
{
  return uct_bxi_ep_atomic_fetch_common(tl_ep, opcode, (uint64_t)value,
                                        (uint64_t *)result, sizeof(uint32_t),
                                        PTL_UINT32_T, remote_addr, rkey, comp);
}

ucs_status_t uct_bxi_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare,
                                       uint64_t swap, uint64_t remote_addr,
                                       uct_rkey_t rkey, uint64_t *result,
                                       uct_completion_t *comp)
{
  return uct_bxi_ep_atomic_cswap_common(tl_ep, compare, swap, sizeof(uint64_t),
                                        PTL_UINT64_T, remote_addr, rkey, result,
                                        comp);
}

ucs_status_t uct_bxi_ep_atomic64_post(uct_ep_h tl_ep, unsigned opcode,
                                      uint64_t value, uint64_t remote_addr,
                                      uct_rkey_t rkey)
{
  return uct_bxi_ep_atomic_post_common(tl_ep, opcode, value, sizeof(uint64_t),
                                       PTL_UINT64_T, remote_addr, rkey);
}

ucs_status_t uct_bxi_ep_atomic64_fetch(uct_ep_h tl_ep, uct_atomic_op_t opcode,
                                       uint64_t value, uint64_t *result,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp)
{
  return uct_bxi_ep_atomic_fetch_common(tl_ep, opcode, value, result,
                                        sizeof(uint64_t), PTL_UINT64_T,
                                        remote_addr, rkey, comp);
}

ucs_status_t uct_bxi_ep_flush(uct_ep_h tl_ep, unsigned flags,
                              uct_completion_t *comp)
{
  uct_bxi_iface_send_op_t *op = NULL;
  uct_bxi_ep_t            *ep = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface      = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);

  UCT_CHECK_PARAM(!ucs_test_all_flags(flags, UCT_FLUSH_FLAG_CANCEL |
                                                     UCT_FLUSH_FLAG_REMOTE),
                  "flush flags CANCEL and REMOTE are mutually exclusive");

  //NOTE: Endpoint cannot be flushed if there are no resources since there
  //      may be requests in the pending list. They must be processed before
  //      this flush request.
  UCT_BXI_CHECK_IFACE_RES(iface);

  if (ucs_list_is_empty(&ep->send_ops)) {
    return UCS_OK;
  }

  if (flags & UCT_FLUSH_FLAG_REMOTE) {
    if (!(ep->flags & UCT_BXI_EP_FLUSH_REMOTE)) {
      return UCS_INPROGRESS;
    }
    uct_bxi_ep_disable_flush(ep);
  }

  if (comp != NULL) {
    op = ucs_mpool_get(&iface->tx.flush_ops_mp);
    if (op == NULL) {
      return UCS_ERR_NO_MEMORY;
    }
    op->user_comp = comp;
    op->handler   = uct_bxi_ep_flush_comp_op_handler;
    op->flags     = UCT_BXI_IFACE_SEND_OP_FLAG_FLUSH;

    /* Append operation descriptor to completion queue. */
    //NOTE: Do not increment the MD sequence number since we only need to know
    //      when is the last operation completed.
    uct_bxi_ep_add_flush_op_sn(ep, op, iface->tx.mem_desc->sn);
  }

  return UCS_INPROGRESS;
}

ucs_status_t uct_bxi_ep_fence(uct_ep_h tl_ep, unsigned flags)
{
  return uct_bxi_iface_fence(tl_ep->iface, flags);
}

ucs_status_t uct_bxi_ep_get_address(uct_ep_h tl_ep, uct_ep_addr_t *addr)
{
  uct_bxi_ep_t      *ep       = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_ep_addr_t *ptl_addr = (uct_bxi_ep_addr_t *)addr;

  ptl_addr->iface_addr = ep->iface_addr;

  return UCS_OK;
}

int uct_bxi_ep_is_connected(const uct_ep_h                      tl_ep,
                            const uct_ep_is_connected_params_t *params)
{
  int                    is_connected = 1;
  uct_bxi_ep_t          *ep           = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_device_addr_t *dest_device_addr;
  uct_bxi_iface_addr_t  *dest_iface_addr;

  UCT_EP_IS_CONNECTED_CHECK_DEV_IFACE_ADDRS(params);

  dest_device_addr = (uct_bxi_device_addr_t *)params->device_addr;
  dest_iface_addr  = (uct_bxi_iface_addr_t *)params->iface_addr;

  if (!uct_bxi_iface_cmp_device_addr(&ep->dev_addr, dest_device_addr) ||
      !uct_bxi_iface_cmp_iface_addr(&ep->iface_addr, dest_iface_addr)) {
    is_connected = 0;
  }

  return is_connected;
}

//TODO: use arbiter group on each endpoint to enforce fairness between endpoints.
ucs_status_t uct_bxi_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *req,
                                    unsigned flags)
{
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);

  if (uct_bxi_iface_available(iface) > 0 &&
      !ucs_mpool_is_empty(&iface->tm.recv_block_mp)) {
    return UCS_ERR_BUSY;
  }

  uct_pending_req_queue_push(&iface->tx.pending_q, req);
  UCT_TL_EP_STAT_PEND(&ep->super);
  return UCS_OK;
}

static ucs_status_t uct_bxi_ep_check_send(uct_ep_h          tl_ep,
                                          uct_completion_t *comp)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_IFACE_RES(iface);

  // Send 0 length message, set length to 1 to pass IOV check.
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_comp_op_handler, 1);

  /* Endpoint status is checked on the RMA PTE since we do not need 
   * to generate an event on the target. */
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, 0, 0, PTL_ACK_REQ,
                               ep->dev_addr.pid, ep->iface_addr.rma, 0, 0, op,
                               0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut ep check return %d", status);
  }

  /* Append operation descriptor to completion queue and increment 
   * memory descriptor sequence number. */
  uct_bxi_ep_add_send_op_sn(ep, op, iface->tx.mem_desc->sn++);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super.super, PUT, SHORT, 0);
  uct_bxi_log_put(iface);

  return status;
}

static ucs_status_t uct_bxi_ep_check_progress(uct_pending_req_t *uct_req)
{
  uct_bxi_pending_req_t *req = ucs_derived_of(uct_req, uct_bxi_pending_req_t);

  return uct_bxi_ep_check_send(&req->init.ep->super.super, req->init.comp);
}

ucs_status_t uct_bxi_ep_check(uct_ep_h tl_ep, unsigned flags,
                              uct_completion_t *comp)
{
  ucs_status_t           status;
  uct_bxi_ep_t          *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t       *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_pending_req_t *req;

  UCT_EP_KEEPALIVE_CHECK_PARAM(flags, comp);

  ucs_assert(ep->conn_state == UCT_BXI_EP_CONN_CONNECTED);

  if (ep->flags & UCT_BXI_EP_KEEP_ALIVE_PENDING) {
    return UCS_OK;
  }

  status = uct_bxi_ep_check_send(tl_ep, comp);
  if (status != UCS_ERR_NO_RESOURCE) {
    return status;
  }

  req = ucs_mpool_get(&iface->tx.pending_mp);
  if (req == NULL) {
    return UCS_ERR_NO_MEMORY;
  }

  req->init.ep     = ep;
  req->init.comp   = comp;
  req->super.func  = uct_bxi_ep_check_progress;
  ep->flags       |= UCT_BXI_EP_KEEP_ALIVE_PENDING;
  status           = uct_bxi_ep_pending_add(&ep->super.super, &req->super, 0);

  ucs_assert_always(status == UCS_OK);

  return UCS_OK;
}

void uct_bxi_ep_pending_purge_cb(uct_pending_req_t *self, void *arg)
{
  uct_bxi_pending_purge_arg_t *purge_arg = arg;

  purge_arg->cb(self, purge_arg->arg);
}

void uct_bxi_ep_pending_purge(uct_ep_h tl_ep, uct_pending_purge_callback_t cb,
                              void *arg)
{
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_pending_req_priv_queue_t UCS_V_UNUSED *priv;
  uct_bxi_pending_purge_arg_t                purge_arg;

  purge_arg.cb  = cb;
  purge_arg.arg = arg;

  uct_pending_queue_purge(priv, &iface->tx.pending_q, 1,
                          uct_bxi_ep_pending_purge_cb, &purge_arg);
}

UCS_CLASS_INIT_FUNC(uct_bxi_ep_t, const uct_ep_params_t *params)
{
  ucs_status_t     status;
  uct_bxi_iface_t *iface = ucs_derived_of(params->iface, uct_bxi_iface_t);

  UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super);

  self->dev_addr   = *(uct_bxi_device_addr_t *)params->dev_addr;
  self->iface_addr = *(uct_bxi_iface_addr_t *)params->iface_addr;
  self->conn_state = UCT_BXI_EP_CONN_CONNECTED;

  ucs_list_head_init(&self->send_ops);
  self->flags = 0;

  status = uct_bxi_iface_add_ep(iface, self);
  ucs_assert_always(status == UCS_OK);

  return status;
}

static UCS_CLASS_CLEANUP_FUNC(uct_bxi_ep_t)
{
  uct_bxi_iface_t *iface =
          ucs_derived_of(self->super.super.iface, uct_bxi_iface_t);

  uct_bxi_ep_pending_purge(&self->super.super,
                           ucs_empty_function_do_assert_void, NULL);

  uct_bxi_iface_ep_remove(iface, self);
  return;
}

UCS_CLASS_DEFINE(uct_bxi_ep_t, uct_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_bxi_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_bxi_ep_t, uct_ep_t);
