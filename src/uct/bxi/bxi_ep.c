#include "bxi_ep.h"
#include "bxi_iface.h"
#include "bxi_log.h"
#include "bxi_rxq.h"

#include <sys/types.h>
#include <time.h>
#include <ucs/profile/profile.h>
#include <uct/base/uct_log.h>

//NOTE: No overflow event needs to be handled since the message will either:
//      - generate a PTL_EVENT_PUT in a block in the overflow list, block will
//      then be cancelled/unlinked, or
//      - generate a PTL_EVENT_PUT in the priority list.
#define UCT_BXI_ME_OPT_RECV_ZCOPY                                              \
  PTL_ME_OP_PUT | PTL_ME_USE_ONCE | PTL_ME_EVENT_LINK_DISABLE |                \
          PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_EVENT_OVER_DISABLE
#define UCT_BXI_ME_OPT_RECV_ZCOPY_OFFLOADED                                    \
  PTL_ME_OP_PUT | PTL_ME_USE_ONCE | PTL_ME_EVENT_LINK_DISABLE |                \
          PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_EVENT_CT_COMM |                 \
          PTL_ME_EVENT_CT_OVERFLOW | PTL_ME_EVENT_CT_BYTES

#define UCT_BXI_CT_INC (ptl_ct_event_t){.success = 1, .failure = 0}

ptl_op_t uct_bxi_atomic_op_table[] = {
        [UCT_ATOMIC_OP_ADD] = PTL_SUM,   [UCT_ATOMIC_OP_AND] = PTL_BAND,
        [UCT_ATOMIC_OP_OR] = PTL_BOR,    [UCT_ATOMIC_OP_XOR] = PTL_BXOR,
        [UCT_ATOMIC_OP_SWAP] = PTL_SWAP, [UCT_ATOMIC_OP_CSWAP] = PTL_CSWAP,
};

static UCS_F_ALWAYS_INLINE void
uct_bxi_ep_remove_from_queue(uct_bxi_iface_send_op_t *op)
{
  ucs_list_del(&op->elem);
}

void uct_bxi_ep_get_bcopy_handler(uct_bxi_iface_send_op_t *op, const void *resp)
{
  op->get.unpack_cb(op->get.unpack_arg, resp, op->length);

  uct_invoke_completion(op->user_comp, UCS_OK);

  uct_bxi_ep_remove_from_queue(op);
}

void uct_bxi_ep_get_bcopy_handler_no_completion(uct_bxi_iface_send_op_t *op,
                                                const void              *resp)
{
  op->get.unpack_cb(op->get.unpack_arg, resp, op->length);

  uct_bxi_ep_remove_from_queue(op);
}

static void uct_bxi_send_op_no_completion(uct_bxi_iface_send_op_t *op,
                                          const void              *resp)
{
  uct_bxi_ep_remove_from_queue(op);
}

static void uct_bxi_send_ato_op_no_completion(uct_bxi_iface_send_op_t *op,
                                              const void              *resp)
{
  //FIXME: host memory between two consecutive atomic operations may not be
  //       coherent, thus we need a synchronization. This should happen only
  //       for intranode atomics.
  if (uct_bxi_ep_is_intra_node(op->ep)) {
    PtlAtomicSync();
  }
  uct_bxi_ep_remove_from_queue(op);
}

static void uct_bxi_send_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                         const void              *resp)
{
  uct_invoke_completion(op->user_comp, UCS_OK);

  uct_bxi_ep_remove_from_queue(op);
}

static void uct_bxi_send_comp_ato_op_handler(uct_bxi_iface_send_op_t *op,
                                             const void              *resp)
{
  uct_invoke_completion(op->user_comp, UCS_OK);

  //FIXME: see FIXME above.
  if (uct_bxi_ep_is_intra_node(op->ep)) {
    PtlAtomicSync();
  }
  uct_bxi_ep_remove_from_queue(op);
}

static void uct_bxi_send_rndv_no_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                                 const void              *resp)
{
  uct_bxi_recv_block_release(op->rndv.block);
  uct_bxi_ep_remove_from_queue(op);
}

static void uct_bxi_send_rndv_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                              const void              *resp)
{
  uct_invoke_completion(op->user_comp, UCS_OK);

  uct_bxi_recv_block_release(op->rndv.block);
  uct_bxi_ep_remove_from_queue(op);
}

//TODO: consider moving uct_bxi_send_rndv_cancel_completion to
//      uct_bxi_iface_completion_op

/* Callback of sender for rendezvous protocol. */
static void uct_bxi_send_rndv_cancel_completion(uct_bxi_iface_send_op_t *op,
                                                const void              *resp)
{
  /* Do not call user completion callback as it's been acknowledged already 
   * during the sw protocol handled by UCP. */
  uct_bxi_ep_remove_from_queue(op);
}

static void uct_bxi_ep_flush_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                             const void              *resp)
{
  uct_invoke_completion(op->user_comp, UCS_OK);

  uct_bxi_ep_remove_from_queue(op);
}

/* Callback of receiver for rendezvous protocol. */
static void uct_bxi_recv_rndv_tag_handler(uct_bxi_iface_send_op_t *op,
                                          const void              *resp)
{
  uct_bxi_recv_block_t *block = op->rndv.block;

  if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOADED) {
    uct_bxi_recv_block_update_cnt(block, 1);
  }

  /* Invoke tag-related callback. */
  block->ctx->completed_cb(
          block->ctx, block->stag, 0, block->send_size, NULL,
          block->size < block->send_size ? UCS_ERR_MESSAGE_TRUNCATED : UCS_OK);

  uct_bxi_recv_block_release(block);
}

static ucs_status_t uct_bxi_iface_block_handle_rndv(uct_bxi_iface_t      *iface,
                                                    uct_bxi_recv_block_t *block,
                                                    ptl_event_t          *ev)
{
  /* Block was posted during rendez-vous. Event means target has successfully
   * read data, initiator's operation can thus be completed. Block is released 
   * in uct_bxi_send_rndv_comp_op_handler. */
  uct_bxi_iface_completion_op(block->op);

  return UCS_OK;
}

ucs_status_t uct_bxi_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t hdr,
                                 const void *buffer, unsigned length)
{
  ucs_status_t     status = UCS_OK;
  uct_bxi_ep_t    *ep     = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface  = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;
  size_t                   size = length + sizeof(hdr);

  UCT_BXI_CHECK_AM_SHORT(id, length, uint64_t, iface->config.max_inline);
  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  UCT_BXI_IFACE_GET_TX_OP(iface, &iface->tx.send_op_mp, op, ep, size);

  /* Copy on the stack allocated buffer. */
  *(uint64_t *)iface->tx.short_desc = hdr;
  memcpy(UCS_PTR_BYTE_OFFSET(iface->tx.short_desc, sizeof(hdr)), buffer,
         length);

  //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlPut(
          iface->tx.mem_desc->mdh, (ptl_size_t)iface->tx.short_desc, size,
          PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.am, id, 0, op, 0));

  if (status == UCS_ERR_NO_RESOURCE) {
    goto err_release_op;
  } else if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut short return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, AM, SHORT, length);
  uct_bxi_iface_trace_am(ucs_derived_of(tl_ep->iface, uct_bxi_iface_t),
                         UCT_AM_TRACE_TYPE_SEND, id, buffer, size);

  return status;

err_release_op:
  ucs_mpool_put(op);
  return status;
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_AM_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                     pack, arg, &size);
  if (size < 0) {
    goto err;
  }

  //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               size, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.am, id, 0, op, 0));

  if (status == UCS_ERR_NO_RESOURCE) {
    size = UCS_ERR_NO_RESOURCE;
    goto err_release_op;
  } else if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, AM, BCOPY, size);
  uct_bxi_iface_trace_am(ucs_derived_of(tl_ep->iface, uct_bxi_iface_t),
                         UCT_AM_TRACE_TYPE_SEND, id, op + 1, size);

  return size;
err_release_op:
  ucs_mpool_put(op);
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  UCT_BXI_IFACE_GET_TX_OP(iface, &iface->tx.send_op_mp, op, ep, length);

  //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)buffer,
                               length, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.rma, 0, remote_addr, op, 0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut short return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);

  //ucs_debug("BXI: available=%lu, desc=%d", iface->tx.available,
  //          iface->tx.num_elems);
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_PUT_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                      pack_cb, arg, size);
  if (size < 0) {
    goto err;
  }

  //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               size, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.rma, 0, remote_addr, op, 0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_comp_op_handler,
                               uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov  = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  iov_size = uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);
  UCT_SKIP_ZERO_LENGTH(iov_size);

  //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
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

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);
  UCT_TL_EP_STAT_OP(&ep->super, PUT, ZCOPY, uct_iov_total_length(iov, iovcnt));
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_GET_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                      unpack_cb, comp, arg, length);

  //TODO: replace by PtlGetNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlGet(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               length, ep->dev_addr.pid, ep->iface_addr.rma, 0,
                               remote_addr, op));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlGet bcopy return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }
  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_comp_op_handler,
                               uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov  = ucs_alloca(iovcnt * sizeof(ptl_size_t));
  iov_size = uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);
  UCT_SKIP_ZERO_LENGTH(iov_size);

  //TODO: replace by PtlGetNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlGet(iface->tx.mem_desc->mdh,
                               (ptl_size_t)ptl_iov->iov_base, ptl_iov->iov_len,
                               ep->dev_addr.pid, ep->iface_addr.rma, 0,
                               remote_addr, op));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlGet bcopy return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }
  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, GET, ZCOPY, uct_iov_total_length(iov, iovcnt));
  uct_bxi_log_put(iface);

err:
  return status;
}

ucs_status_t uct_bxi_ep_tag_eager_short(uct_ep_h tl_ep, uct_tag_t tag,
                                        const void *data, size_t length)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  //FIXME: use length > 0 to pass LENGTH test.
  UCT_BXI_IFACE_GET_TX_OP(iface, &iface->tx.send_op_mp, op, ep, 1);

  //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)data,
                               length, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.tag, tag, 0, op, 0));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut short return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_inc_send_cnt(iface, ep->idx);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, TAG, SHORT, length);
  uct_bxi_log_put(iface);

err:
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
  uct_bxi_gop_t   *gop;
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  if (ucs_unlikely(flags & UCT_TAG_SCHEDULE)) {
    gop  = arg;
    size = gop->super.size;

    UCT_BXI_IFACE_GET_TX_TAG_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, NULL,
                                     uct_bxi_send_comp_op_handler, 0);

    status = uct_bxi_wrap(PtlTriggeredPut(
            iface->tx.mem_desc->mdh, (ptl_size_t)(gop + 1), size, PTL_ACK_REQ,
            ep->dev_addr.pid, ep->iface_addr.tag, tag, 0, op, imm, gop->cth,
            gop->ct_value));
  } else {
    /* Take a bcopy send descriptor from the memory pool. Descriptor has 
     * an operation first, then a buffer of size seg_size. */
    UCT_BXI_IFACE_GET_TX_AM_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                       pack_cb, arg, &size);
    if (size < 0) {
      goto err;
    }

    //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
    status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 size, PTL_ACK_REQ, ep->dev_addr.pid,
                                 ep->iface_addr.tag, tag, 0, op, imm));
  }

  if (status == UCS_ERR_NO_RESOURCE) {
    size = UCS_ERR_NO_RESOURCE;
    goto err_release_op;
  } else if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_inc_send_cnt(iface, ep->idx);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, TAG, BCOPY, size);
  uct_bxi_log_put(iface);

  return size;

err_release_op:
  ucs_mpool_put(op);
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
  ucs_status_t     status;
  ptl_iovec_t     *ptl_iov;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_gop_t   *gop   = ucs_derived_of(comp->gop, uct_bxi_gop_t);
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_ep_get_zcopy");
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_TAG_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                                   uct_bxi_send_comp_op_handler,
                                   uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  if (ucs_unlikely(flags & UCT_TAG_SCHEDULE)) {
    status = uct_bxi_wrap(PtlTriggeredPut(
            iface->tx.mem_desc->mdh, (ptl_size_t)ptl_iov->iov_base,
            ptl_iov->iov_len, PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.tag,
            tag, 0, op, imm, gop->cth, gop->ct_value));
  } else {
    //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
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

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_inc_send_cnt(iface, ep->idx);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, TAG, ZCOPY, uct_iov_total_length(iov, iovcnt));
  uct_bxi_log_put(iface);

err:
  return status;
}

static inline size_t uct_bxi_pack_rndv(uct_bxi_iface_t *iface, void *dest,
                                       void *src, size_t length,
                                       const void *header,
                                       unsigned    header_length)
{
  uct_bxi_hdr_rndv_t *hdr =
          UCS_PTR_BYTE_OFFSET(dest, iface->tm.rndv_hdr_offset);

  /* First copy the payload up to buffer capacity minus size required for the 
   * rndv hdr and the user header. */
  memcpy(dest, src, ucs_min(length, iface->tm.rndv_hdr_offset));

  hdr->remote_addr   = (uint64_t)src;
  hdr->header_length = header_length;

  memcpy(hdr + 1, header, header_length);

  ucs_assert(iface->tm.rndv_hdr_offset + sizeof(uct_bxi_hdr_rndv_t) +
                     header_length <=
             iface->config.tm.eager_limit + 1);

  return iface->config.tm.eager_limit + 1;
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
  uct_bxi_gop_t   *gop   = ucs_derived_of(comp->gop, uct_bxi_gop_t);
  uct_bxi_iface_send_op_t *op;
  ptl_me_t                 me;
  uct_bxi_recv_block_t    *block;
  ptl_hdr_data_t           hdr = 0;
  ssize_t                  bsize;

  UCT_BXI_CHECK_EP_PTR(ep);
  UCT_BXI_CHECK_IOV_SIZE_PTR(iovcnt, (unsigned long)iface->config.max_iovecs,
                             "uct_bxi_ep_tag_rndv_zcopy");
  UCT_BXI_CHECK_IFACE_RES_PTR(iface, ep);

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  /* First, allocate a TAG block from the memory pool. Receive block is 
   * used to match the remote GET operation and is posted to the CTRL RXQ. 
   * Reduce it off of the eager size that will be sent. */
  bsize = ucs_max((ssize_t)(ptl_iov->iov_len - iface->tm.rndv_hdr_offset), 0);
  UCT_BXI_IFACE_GET_RX_TAG_DESC_ERR(
          iface, &iface->tm.recv_block_mp, block,
          UCS_PTR_BYTE_OFFSET(ptl_iov->iov_base, iface->tm.rndv_hdr_offset),
          bsize, iface->tm.cnts[ep->idx].send, NULL,
          uct_bxi_iface_block_handle_rndv, status = UCS_ERR_NO_RESOURCE;
          goto err);

  me.start             = block->start;
  me.length            = block->size;
  me.match_bits        = block->tag;
  me.match_id.phys.nid = ep->dev_addr.pid.phys.nid;
  me.match_id.phys.pid = ep->dev_addr.pid.phys.pid;
  me.uid               = PTL_UID_ANY;
  me.ct_handle         = PTL_CT_NONE;
  me.ignore_bits       = 0;
  me.options           = PTL_ME_OP_GET | PTL_ME_EVENT_LINK_DISABLE |
               PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_MAY_ALIGN |
               PTL_ME_IS_ACCESSIBLE | PTL_ME_USE_ONCE;

  /* Then, post the memory entry to the CTRL RXQ. Target will execute 
   * a GET operation on this. */
  status = uct_bxi_recv_block_exp_activate(iface->rx.ctrl.q, block, &me);
  if (status != UCS_OK) {
    goto err_release_block;
  }

  /* Now, allocate a send descriptor to pack rendez-vous metadata. */
  UCT_BXI_IFACE_GET_TX_TAG_DESC_ERR(iface, &iface->tx.send_desc_mp, op, ep,
                                    comp, uct_bxi_send_rndv_comp_op_handler,
                                    status = UCS_ERR_NO_RESOURCE;
                                    goto err_deactivate_block);

  /* Rendez-vous operation will creates two events: 
   * - PTL_EVENT_ACK: acknowledge the reception of the first control message
   * - PTL_EVENT_GET/PTL_EVENT_PUT: target has issued the GET operation and 
   *   has retrieved the data or first message was received as unexpected, 
   *   thus initiator will receive a PUT event and rendezvous will be 
   *   cancelled.
   * Therefore, we increment the completion counter so that the operation is 
   * actually completed when both of them were treated. */
  op->comp.comp++;

  /* Attach operation to block and vice versa so they can be both released, 
   * either on PTL_EVENT_GET completion or if the operation is canceled. */
  block->op      = op;
  op->rndv.block = block;

  /* Operation length must be eager_limit + 1 to triggered remote get in case
   * the receive has been posted early. */
  op->length = uct_bxi_pack_rndv(iface, op + 1, ptl_iov->iov_base,
                                 ptl_iov->iov_len, header, header_length);

  UCT_BXI_RNDV_HDR_SET(hdr, ptl_iov->iov_len, iface->tm.cnts[ep->idx].send,
                       iface->rx.ctrl.q->pti);

  if (ucs_unlikely(flags & UCT_TAG_SCHEDULE)) {
    /* An operation context was provided, so the operation must be 
     * triggered. */
    ucs_assert(!PtlHandleIsEqual(gop->cth, PTL_INVALID_HANDLE));

    status = uct_bxi_wrap(PtlTriggeredPut(
            iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1), op->length,
            PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.tag, tag, 0, op, hdr,
            gop->cth, gop->ct_value));
  } else {
    //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
    status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 op->length, PTL_ACK_REQ, ep->dev_addr.pid,
                                 ep->iface_addr.tag, tag, 0, op, hdr));
  }
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut rndv zcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_inc_send_cnt(iface, ep->idx);
  uct_bxi_ep_enable_flush(ep);

  return (ucs_status_ptr_t)op;

err_deactivate_block:
  uct_bxi_recv_block_deactivate(block);
err_release_block:
  uct_bxi_recv_block_release(block);
err:
  return UCS_STATUS_PTR(status);
}

ucs_status_t uct_bxi_ep_tag_rndv_cancel(uct_ep_h tl_ep, void *tl_op)
{
  uct_bxi_iface_send_op_t *op = (uct_bxi_iface_send_op_t *)tl_op;

  /* Deactivate and release block. */
  uct_bxi_recv_block_deactivate(op->rndv.block);
  uct_bxi_recv_block_release(op->rndv.block);

  /* Overwrite completion handler. */
  op->comp.handler = uct_bxi_send_rndv_cancel_completion;

  // NOTE: Uncertain if PTL_EVENT_ACK from the rendezvous message has
  //       been processed, so we can't return the operation to the pool.
  //       This is checked by the completion counter. Since the initiator
  //       has received the RTR message from the target, there's no need
  //       to invoke the user's completion callback.
  uct_bxi_iface_completion_op(op);

  return UCS_OK;
}

ucs_status_t uct_bxi_ep_tag_rndv_request(uct_ep_h tl_ep, uct_tag_t tag,
                                         const void *header,
                                         unsigned header_length, unsigned flags)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_LENGTH(header_length, 0, iface->config.seg_size,
                   "tag_rndv_request");
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  //NOTE: rndv_request cannot be offloaded since the rest of the protocol has
  //      to be done in software. This is the case with generic datatype, very
  //      large message or multiple iov since current hardwares do not support
  //      it.
  ucs_assert(!(flags & UCT_TAG_SCHEDULE));

  /* Allocate a send descriptor to pack rendez-vous metadata. */
  UCT_BXI_IFACE_GET_TX_TAG_OP_COMP(iface, &iface->tx.send_desc_mp, op, ep, NULL,
                                   uct_bxi_send_op_no_completion, 0);

  memcpy(op + 1, header, header_length);

  //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               header_length, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.tag, tag, 0, op,
                               UCT_BXI_RNDV_SW_HDR));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut rndv request return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_inc_send_cnt(iface, ep->idx);
  uct_bxi_ep_enable_flush(ep);

err:
  return status;
}

static UCS_F_ALWAYS_INLINE int
uct_bxi_tag_recv_offload_rndv(uct_bxi_iface_t      *iface,
                              uct_bxi_recv_block_t *block, uct_bxi_ep_t *ep)
{
  return (block->size > iface->config.tm.eager_limit) &&
         (block->size <= iface->config.max_msg_size) && (ep != NULL);
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_iface_tag_recv_rndv_zcopy(uct_bxi_iface_t *iface, uct_bxi_ep_t *ep,
                                  uct_bxi_recv_block_t *block, ptl_me_t *me)
{
  ucs_status_t status = UCS_OK;
  ptl_size_t   start;

  start = (ptl_size_t)UCS_PTR_BYTE_OFFSET(block->start,
                                          iface->tm.rndv_hdr_offset);

  block->op->length = block->size - iface->tm.rndv_hdr_offset;

  /* TriggeredGet at current counter value plus eager_limit + 1, as defined by 
   * Barrett and al. */
  //FIXME: block MD is used in all cases. Thus, whether the operation is
  //       offloaded or not, counter will be incremented. However, it is not
  //       absolutely necessary when operation is not offloaded.
  status = uct_bxi_wrap(PtlTriggeredGet(
          block->mdh, start, block->op->length, ep->dev_addr.pid,
          ep->iface_addr.ctrl, iface->tm.cnts[ep->idx].recv, 0, block->op,
          block->cth, block->ct_value + iface->config.tm.eager_limit + 1));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlTriggeredGet request return %d", status);
  }
}

//TODO: better handler receive completion mecanisms. It's a mess right now.
UCS_PROFILE_FUNC(ucs_status_t, uct_bxi_iface_tag_recv_zcopy,
                 (tl_iface, tag, tag_mask, iov, iovcnt, ctx),
                 uct_iface_h tl_iface, uct_tag_t tag, uct_tag_t tag_mask,
                 const uct_iov_t *iov, size_t iovcnt, uct_tag_context_t *ctx)
{
  ucs_status_t          status;
  ptl_iovec_t          *ptl_iov;
  uct_bxi_iface_t      *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);
  uct_bxi_ep_t         *ep    = ucs_derived_of(ctx->reply_ep, uct_bxi_ep_t);
  uct_bxi_recv_block_t *block;
  ptl_me_t              me;

  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_iface_tag_recv_zcopy");

  /* The same tag cannot be associated to the same buffer. */
  //TODO: this is true for InfiniBand, but to be verified for Portals4.
  status = uct_bxi_iface_tag_add_to_hash(iface, iov->buffer);
  if (status != UCS_OK) {
    goto err;
  }

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  /* First, allocate a TAG block from the memory pool. */
  //NOTE: iov length may be 0 and thus we loose the buffer address when filling
  //      the ptl_iov. Block buffer is thus set using iov->buffer instead of
  //      ptl_iov.
  UCT_BXI_IFACE_GET_RX_TAG_DESC_ERR(iface, &iface->tm.recv_block_mp, block,
                                    iov->buffer, ptl_iov->iov_len, tag, ctx,
                                    uct_bxi_iface_block_handle_tag_exp,
                                    status = UCS_ERR_EXCEEDS_LIMIT;
                                    goto err_remove_hash);

  if (uct_bxi_iface_has_tx_resources(iface) <= 0) {
    return UCS_ERR_NO_RESOURCE;
  }

  /* An operation is needed in case a rendezvous message is received, because the
   * rendezvous threshold is configurable at runtime, we always need to allocate it.
   * Here are the possible paths:
   * - wrong prediction and eager msg was received instead, then the operation 
   *   is not used and just released before block release,
   * - endpoint was not provided, thus the operation is used to complete the 
   *   protocol upon event handling, 
   * - otherwise, operation will be triggered. */
  UCT_BXI_IFACE_GET_TX_RNDV_OP_ERR(iface, &iface->tx.send_op_mp, block->op, ep,
                                   block->size, block,
                                   status = UCS_ERR_NO_RESOURCE;
                                   goto err_release_block;);
  /* There are two stages to complete the operation, and the end of each stage 
   * will call the operation completion handler:
   * 1) Matching: either expectedly or unexpectedly, see 
   *    uct_bxi_iface_block_handle_tag_exp and 
   *    uct_bxi_iface_block_handle_tag_overflow.
   * 2) GET: through PTL_EVENT_REPLY, meaning that data was completely read from 
   * the initiator. 
   * If eager or sw rndv is received, then the operation will be released 
   * directly. */
  block->op->comp.comp++;

  /* Initialise ME params with default value, they may be changed during 
   * protocol configuration below. For eager message and without generic 
   * operation, no counter is needed on the ME. */
  me.ct_handle         = PTL_CT_NONE;
  me.options           = UCT_BXI_ME_OPT_RECV_ZCOPY;
  me.match_id.phys.nid = PTL_NID_ANY;
  me.match_id.phys.pid = PTL_PID_ANY;
  me.uid               = PTL_UID_ANY;

  /* If receive size if lower than the eager limit, then the rendezvous can
   * never be offloaded. However, the rendezvous threshold is configurable by 
   * the upper layer meaning that the sender may decide to send a rendezvous 
   * control message even though msg_size < eager_limit. As a consequence, 
   * the protocol will be completed during event handling. */
  if (ucs_unlikely(uct_bxi_tag_recv_offload_rndv(iface, block, ep) ||
                   iface->tm.sched_window)) {
    /* Counter is needed. */
    block->flags |= UCT_BXI_RECV_BLOCK_FLAG_COUNTER_ENABLED;
    /* Update ME parameters. */
    me.ct_handle = block->cth;
    me.options   = UCT_BXI_ME_OPT_RECV_ZCOPY_OFFLOADED;

    if (uct_bxi_tag_recv_offload_rndv(iface, block, ep)) {
      /* Then is means the rendezvous will be offloaded. */
      block->flags |= UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOADED;
    }
  }

  me.start       = block->start;
  me.length      = block->size;
  me.match_bits  = tag;
  me.ignore_bits = ~tag_mask;

  /* Then, post the memory entry. */
  status = uct_bxi_recv_block_exp_activate(iface->rx.tag.q, block, &me);
  if (status != UCS_OK) {
    /* Operation will be released with block release. */
    goto err_release_op;
  }

  if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOADED) {
    uct_bxi_iface_tag_recv_rndv_zcopy(iface, ep, block, &me);
  }

  /* Update interface available resources. */
  uct_bxi_iface_op_res(iface, block->op);
  if (ep != NULL) {
    uct_bxi_ep_inc_recv_cnt(iface, ep->idx);
  }

  *(uct_bxi_recv_block_t **)ctx->priv = block;

  return status;

err_release_op:
  uct_bxi_iface_release_op(block->op);
err_release_block:
  uct_bxi_recv_block_release(block);
err_remove_hash:
  uct_bxi_iface_tag_del_from_hash(iface, iov->buffer);
err:
  return status;
}

ucs_status_t uct_bxi_iface_tag_recv_cancel(uct_iface_h        tl_iface,
                                           uct_tag_context_t *ctx,
                                           unsigned           mode)
{
  uct_bxi_recv_block_t *block = *(uct_bxi_recv_block_t **)ctx->priv;
  uct_bxi_iface_t      *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);

  if (mode & UCT_TAG_CANCEL_FORCE) {
    uct_bxi_iface_tag_del_from_hash(iface, block->start);
  }

  /* Receive has been posted and thus counter has been incremented two 
   * times (either through MATCHED or CANCEL). Only do so if reply 
   * endpoint was provided during post. */
  if (block->op->ep != NULL) {
    uct_bxi_ep_dec_recv_cnt(iface, block->op->ep->idx);
  }

  /* Posted receive was matched in overflow list, unexpected header was then 
   * consumed and ME unlinked already. Decrement counter to notify 
   * uct_bxi_iface_block_handle_tag_events. */
  if (mode & UCT_TAG_CANCEL_MATCHED) {
    //TODO: add test to check recv + recv_cancel to make sure unexp_hdr_count
    //      does not overflow. This could happen in the later.
    iface->tm.unexp_hdr_count--;

    /* Rendezvous was offloaded, thus an PTL_EVENT_PUT_OVERFLOW will be 
     * generated. Overwrite the block handler to handle it during which the 
     * block will be released */
    block->handler = uct_bxi_iface_block_handle_tag_overflow;
    if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOADED) {
      return UCS_INPROGRESS;
    } else if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_COUNTER_ENABLED) {
      return UCS_OK;
    }
  } else {
    /* Otherwise, block needs to be explicitly unlinked. */
    uct_bxi_recv_block_deactivate(block);
  }

  uct_bxi_iface_release_op(block->op);

  if (mode & UCT_TAG_CANCEL_FORCE) {
    uct_bxi_recv_block_release(block);
  } else {
    //FIXME: due to noforce UCT tests, block need to be cancelled
    //       during polling. Since Unlink does not generate any event, we
    //       are required to maintain a list of cancelled blocks.
    ucs_list_add_head(&iface->rx.tag.cancel, &block->c_elem);
  }

  return UCS_OK;
}

ucs_status_t uct_bxi_iface_tag_sched_enable(uct_iface_h tl_iface)
{
  uct_bxi_iface_t *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);

  iface->tm.sched_window = 1;

  return UCS_OK;
}

void uct_bxi_iface_tag_sched_disable(uct_iface_h tl_iface)
{
  uct_bxi_iface_t *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);

  iface->tm.sched_window = 0;
}

ucs_status_t uct_bxi_iface_tag_sched_recv(uct_iface_h        tl_iface,
                                          uct_tag_context_t *ctx,
                                          uct_gop_h         *gop_p)
{
  ucs_status_t          status = UCS_OK;
  uct_bxi_gop_t        *gop;
  uct_bxi_iface_t      *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);
  uct_bxi_recv_block_t *block = *(uct_bxi_recv_block_t **)ctx->priv;
  size_t                thresh;

  gop = ucs_mpool_get(&iface->tm.gop_mp);
  if (gop == NULL) {
    ucs_debug("BXI: no more counter");
    status = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  if (ucs_unlikely(block->flags & UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOADED)) {
    /* thresh = current counter value + eager limit + 1 + 
     * completion of get (+1) */
    thresh = block->ct_value + iface->config.tm.eager_limit + 2;
  } else {
    thresh = block->ct_value + block->size;
  }

  status = uct_bxi_wrap(
          PtlTriggeredCTInc(gop->cth, UCT_BXI_CT_INC, block->cth, thresh));
  if (status != UCS_OK) {
    ucs_fatal("BXI: could not trig ct inc.");
  }
  gop->ct_value += 1;

  *gop_p = (uct_gop_h)gop;

  return status;

err_free_gop:
  ucs_mpool_put(gop);
err:
  return status;
}

ucs_status_t uct_bxi_iface_tag_sched_send(uct_iface_h tl_iface,
                                          uct_gop_h *gop_p, uct_gop_h *tl_gops,
                                          size_t gop_cnt)
{
  ucs_status_t     status = UCS_OK;
  uct_bxi_iface_t *iface  = ucs_derived_of(tl_iface, uct_bxi_iface_t);
  uct_bxi_gop_t   *gop;
  uct_bxi_gop_t   *tmp_gop;
  size_t           i;

  if (gop_cnt == 0) {
    *gop_p = NULL;
    return UCS_OK;
  }

  if (gop_cnt > 1) {
    gop = ucs_mpool_get(&iface->tm.gop_mp);
    if (gop == NULL) {
      status = UCS_ERR_NO_RESOURCE;
      goto err;
    }

    for (i = 0; i < gop_cnt; i++) {
      tmp_gop = ucs_derived_of(tl_gops[i], uct_bxi_gop_t);

      ucs_assert(!PtlHandleIsEqual(tmp_gop->cth, PTL_INVALID_HANDLE));

      status = uct_bxi_wrap(PtlTriggeredCTInc(gop->cth, UCT_BXI_CT_INC,
                                              tmp_gop->cth, tmp_gop->ct_value));
      if (status != UCS_OK) {
        ucs_fatal("BXI: failed setting trig inc.");
      }
      gop->ct_value++;
    }
  } else {
    gop = ucs_derived_of(tl_gops[0], uct_bxi_gop_t);
  }

  *gop_p = (uct_gop_h)gop;

err:
  return status;
}

void uct_bxi_iface_tag_sched_release(uct_iface_h tl_iface, uct_gop_h tl_gop)
{
  uct_bxi_gop_t *gop = ucs_derived_of(tl_gop, uct_bxi_gop_t);

  ucs_mpool_put(gop);
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_ATO_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, NULL,
                                   uct_bxi_send_comp_ato_op_handler, size);

  /* Store the value since the Atomic call needs an address. */
  op->atomic.value = value;

  //TODO: replace by PtlAtomicNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(
          PtlAtomic(iface->tx.mem_desc->mdh, (uint64_t)&op->atomic.value, size,
                    PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.rma, 0,
                    remote_addr, op, 0, uct_bxi_atomic_op_table[opcode], dt));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlAtomic request return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_ATO_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                                   uct_bxi_send_comp_ato_op_handler, size);

  /* Store the value since the Atomic call needs an address. */
  op->atomic.value = value;

  //TODO: replace by PtlFetchAtomicNB and handle PTL_TRY_AGAIN
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

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_ATO_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                                   uct_bxi_send_comp_ato_op_handler, size);

  /* Store the value since the Atomic call needs an address. */
  op->atomic.value   = swap;
  op->atomic.compare = compare;

  //TODO: replace by PtlSwapNB and handle PTL_TRY_AGAIN
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

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  if (ucs_list_is_empty(&ep->send_ops)) {
    UCT_TL_EP_STAT_FLUSH(&ep->super);
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
    op->user_comp    = comp;
    op->comp.handler = uct_bxi_ep_flush_comp_op_handler;
    op->comp.comp    = 1;
    op->flags        = UCT_BXI_IFACE_SEND_OP_FLAG_FLUSH;

    /* Append operation descriptor to completion queue. */
    uct_bxi_ep_add_flush_op(ep, op);
  }

  UCT_TL_EP_STAT_FLUSH_WAIT(&ep->super);
  return UCS_INPROGRESS;
}

ucs_status_t uct_bxi_ep_fence(uct_ep_h tl_ep, unsigned flags)
{
  //NOTE: Fence semantic is to enforce completion of previous operations
  //      and host visibility of memory.
  PtlAtomicSync();

  UCT_TL_EP_STAT_FENCE(ucs_derived_of(tl_ep, uct_base_ep_t));
  return UCS_OK;
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
#ifdef ENABLE_STATS
  uct_bxi_ep_t *ep = ucs_derived_of(tl_ep, uct_bxi_ep_t);
#endif
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);

  if (flags) {
    goto add_to_pending;
  }

  if (uct_bxi_iface_has_tx_resources(iface) > 0 &&
      ((iface->tm.enabled && !ucs_mpool_is_empty(&iface->tm.recv_block_mp)) ||
       !iface->tm.enabled)) {
    return UCS_ERR_BUSY;
  }

add_to_pending:
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

  UCT_BXI_CHECK_IFACE_RES(iface, ep);

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

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, PUT, SHORT, 0);
  uct_bxi_log_put(iface);

  return status;
}

static ucs_status_t uct_bxi_ep_check_progress(uct_pending_req_t *uct_req)
{
  uct_bxi_pending_req_t *req = ucs_derived_of(uct_req, uct_bxi_pending_req_t);

  return uct_bxi_ep_check_send(&req->ep->super.super, req->comp);
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

  req->ep          = ep;
  req->comp        = comp;
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
  uct_bxi_iface_t *iface = ucs_derived_of(params->iface, uct_bxi_iface_t);

  UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super);

  if (iface->num_eps + 1 > iface->config.max_num_eps) {
    return UCS_ERR_NO_RESOURCE;
  }

  self->dev_addr   = *(uct_bxi_device_addr_t *)params->dev_addr;
  self->iface_addr = *(uct_bxi_iface_addr_t *)params->iface_addr;
  self->conn_state = UCT_BXI_EP_CONN_CONNECTED;

  ucs_list_head_init(&self->send_ops);
  self->flags = 0;

  ucs_list_add_head(&iface->eps, &self->elem);
  iface->num_eps++;

  if (iface->tm.enabled) {
    /* Cache counter index for fast access during send operations. */
    self->idx = uct_bxi_iface_get_or_create_cnt_idx(iface, self->dev_addr.pid);
  }

  return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_bxi_ep_t)
{
  uct_bxi_iface_t *iface =
          ucs_derived_of(self->super.super.iface, uct_bxi_iface_t);

  uct_bxi_ep_pending_purge(&self->super.super,
                           ucs_empty_function_do_assert_void, NULL);

  ucs_list_del(&self->elem);
  iface->num_eps--;

  return;
}

UCS_CLASS_DEFINE(uct_bxi_ep_t, uct_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_bxi_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_bxi_ep_t, uct_ep_t);
