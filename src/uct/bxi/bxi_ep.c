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
#define UCT_BXI_ME_OPT_RECV_ZCOPY_CNT                                          \
  PTL_ME_OP_PUT | PTL_ME_USE_ONCE | PTL_ME_EVENT_LINK_DISABLE |                \
          PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_EVENT_OVER_DISABLE |            \
          PTL_ME_EVENT_CT_COMM | PTL_ME_EVENT_CT_OVERFLOW
#define UCT_BXI_ME_OPT_RECV_ZCOPY_CNT_BYTES                                    \
  PTL_ME_OP_PUT | PTL_ME_USE_ONCE | PTL_ME_EVENT_LINK_DISABLE |                \
          PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_EVENT_OVER_DISABLE |            \
          PTL_ME_EVENT_CT_COMM | PTL_ME_EVENT_CT_OVERFLOW |                    \
          PTL_ME_EVENT_CT_BYTES
#define UCT_BXI_ME_OPT_RECV_ZCOPY_TRIG                                         \
  PTL_ME_OP_PUT | PTL_ME_USE_ONCE | PTL_ME_EVENT_LINK_DISABLE |                \
          PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_EVENT_OVER_DISABLE |            \
          PTL_ME_EVENT_CT_COMM | PTL_ME_EVENT_CT_OVERFLOW

uct_bxi_block_cnt_t dummy_cnt = {.threshold = 0, .cth = PTL_CT_NONE};

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
  ucs_mpool_put_inline(op);
}

void uct_bxi_ep_get_bcopy_handler_no_completion(uct_bxi_iface_send_op_t *op,
                                                const void              *resp)
{
  op->get.unpack_cb(op->get.unpack_arg, resp, op->length);

  uct_bxi_ep_remove_from_queue(op);
  ucs_mpool_put_inline(op);
}

static void uct_bxi_send_op_no_completion(uct_bxi_iface_send_op_t *op,
                                          const void              *resp)
{
  uct_bxi_ep_remove_from_queue(op);
  ucs_mpool_put_inline(op);
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
  ucs_mpool_put_inline(op);
}

static void uct_bxi_send_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                         const void              *resp)
{
  uct_invoke_completion(op->user_comp, UCS_OK);

  uct_bxi_ep_remove_from_queue(op);
  ucs_mpool_put_inline(op);
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
  ucs_mpool_put_inline(op);
}

static void uct_bxi_send_rndv_cancel_completion(uct_bxi_iface_send_op_t *op,
                                                const void              *resp)
{
  /* Deactivate block and release it to memory pool. */
  uct_bxi_recv_block_deactivate(op->rndv.block);
  uct_bxi_recv_block_release(op->rndv.block);

  /* Do not call user completion callback as it's been acknowledged already 
   * during the sw protocol handled by UCP. */
  uct_bxi_ep_remove_from_queue(op);
  ucs_mpool_put_inline(op);
}

static void uct_bxi_ep_flush_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                             const void              *resp)
{
  uct_invoke_completion(op->user_comp, UCS_OK);

  uct_bxi_ep_remove_from_queue(op);
  ucs_mpool_put_inline(op);
}

static void uct_bxi_recv_rndv_tag_handler(uct_bxi_iface_send_op_t *op,
                                          const void              *resp)
{
  uct_bxi_recv_block_t *block = op->rndv.block;

  ucs_assert(block->send_size > 0);
  ucs_assert(block->size >= block->send_size);

  /* First, invoke tag-related callback. */
  block->ctx->completed_cb(block->ctx, block->stag, 0, block->send_size, NULL,
                           UCS_OK);

  uct_bxi_ep_remove_from_queue(op);
  /* Finally, we may push OP back to the memory pool. */
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_AM_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                     pack, arg, &size);
  if (size < 0) {
    goto err;
  }

  status = uct_bxi_wrap(PtlPutNB(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 size, PTL_ACK_REQ, ep->dev_addr.pid,
                                 ep->iface_addr.am, id, 0, op, 0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, AM, BCOPY, size);
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  UCT_BXI_IFACE_GET_TX_OP(iface, &iface->tx.send_op_mp, op, ep, length);

  status = uct_bxi_wrap(PtlPutNB(iface->tx.mem_desc->mdh, (ptl_size_t)buffer,
                                 length, PTL_ACK_REQ, ep->dev_addr.pid,
                                 ep->iface_addr.rma, 0, remote_addr, op, 0));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut short return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
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
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_PUT_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                      pack_cb, arg, size);
  if (size < 0) {
    goto err;
  }

  status = uct_bxi_wrap(PtlPutNB(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
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

  status = uct_bxi_wrap(
          PtlPutNB(iface->tx.mem_desc->mdh, (ptl_size_t)ptl_iov->iov_base,
                   ptl_iov->iov_len, PTL_ACK_REQ, ep->dev_addr.pid,
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

  status = uct_bxi_wrap(PtlGetNB(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 length, ep->dev_addr.pid, ep->iface_addr.rma,
                                 0, remote_addr, op));
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

  status = uct_bxi_wrap(PtlGetNB(iface->tx.mem_desc->mdh,
                                 (ptl_size_t)ptl_iov->iov_base,
                                 ptl_iov->iov_len, ep->dev_addr.pid,
                                 ep->iface_addr.rma, 0, remote_addr, op));

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

ucs_status_t uct_bxi_ep_tag_eager_short(uct_ep_h ep, uct_tag_t tag,
                                        const void *data, size_t length)
{
  return UCS_ERR_NOT_IMPLEMENTED;
}

UCS_PROFILE_FUNC(ssize_t, uct_bxi_ep_tag_eager_bcopy,
                 (tl_ep, tag, imm, pack_cb, arg, flags), uct_ep_h tl_ep,
                 uct_tag_t tag, uint64_t imm, uct_pack_callback_t pack_cb,
                 void *arg, unsigned flags)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  ssize_t          size  = 0;
  uct_bxi_gop_t   *gop;
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  if (ucs_unlikely(flags & UCT_TAG_OFFLOAD_OPERATION)) {
    gop  = arg;
    size = gop->super.size;

    UCT_BXI_IFACE_GET_TX_TAG_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, NULL,
                                     uct_bxi_send_comp_op_handler, 0);

    status = uct_bxi_wrap(PtlTriggeredPutNB(
            iface->tx.mem_desc->mdh, (ptl_size_t)(gop + 1), size, PTL_ACK_REQ,
            ep->dev_addr.pid, ep->iface_addr.tag, tag, 0, op, imm, gop->cnt.cth,
            gop->cnt.threshold));
    ucs_debug("BXI: triggered bcopy. nid=%u, pid=%u, size=%lu, op=%p",
              ep->dev_addr.pid.phys.nid, ep->dev_addr.pid.phys.pid, size, op);
  } else {
    /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
    UCT_BXI_IFACE_GET_TX_AM_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                       pack_cb, arg, &size);
    if (size < 0) {
      goto err;
    }

    status = uct_bxi_wrap(PtlPutNB(
            iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1), size, PTL_ACK_REQ,
            ep->dev_addr.pid, ep->iface_addr.tag, tag, 0, op, imm));
  }

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);
  /* Increment endpoint send counter. */
  uct_bxi_ep_tag_inc_cnt(ep);

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

  if (flags & UCT_TAG_OFFLOAD_OPERATION) {
    status = uct_bxi_wrap(PtlTriggeredPutNB(
            iface->tx.mem_desc->mdh, (ptl_size_t)ptl_iov->iov_base,
            ptl_iov->iov_len, PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.tag,
            tag, 0, op, imm, gop->cnt.cth, gop->cnt.threshold));
  } else {
    status = uct_bxi_wrap(
            PtlPutNB(iface->tx.mem_desc->mdh, (ptl_size_t)ptl_iov->iov_base,
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
  uct_bxi_ep_enable_flush(ep);
  /* Increment endpoint send counter. */
  uct_bxi_ep_tag_inc_cnt(ep);

  UCT_TL_EP_STAT_OP(&ep->super, TAG, ZCOPY, uct_iov_total_length(iov, iovcnt));
  uct_bxi_log_put(iface);

err:
  return status;
}

static inline size_t uct_bxi_pack_rndv(uct_bxi_iface_t *iface, void *src,
                                       uint64_t remote_addr, size_t length,
                                       const void *header,
                                       unsigned    header_length)
{
  uct_bxi_hdr_rndv_t *hdr = src;

  hdr->remote_addr   = remote_addr;
  hdr->length        = length;
  hdr->header_length = header_length;

  memcpy(hdr + 1, header, header_length);

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
  uct_bxi_iface_send_op_t    *op;
  uct_bxi_recv_block_params_t params;
  uct_bxi_recv_block_t       *block;
  ptl_hdr_data_t              hdr = 0;

  UCT_BXI_CHECK_EP_PTR(ep);
  UCT_BXI_CHECK_IOV_SIZE_PTR(iovcnt, (unsigned long)iface->config.max_iovecs,
                             "uct_bxi_ep_get_zcopy");
  UCT_BXI_CHECK_IFACE_RES_PTR(iface, ep);

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  /* First, allocate a TAG block from the memory pool. Receive block is 
   * used to match the remote GET operation and is posted to the CTRL RXQ. */
  UCT_BXI_IFACE_GET_RX_TAG_DESC_ERR(
          iface, &iface->tm.recv_block_mp, block, iface->rx.ctrl.q,
          ptl_iov->iov_base, ptl_iov->iov_len,
          UCT_BXI_BUILD_RNDV_TAG(ep->dev_addr.pid, ep->cnt->send), NULL,
          status = UCS_ERR_NO_RESOURCE;
          goto err);

  params.start   = block->start;
  params.size    = block->size;
  params.match   = block->tag;
  params.cth     = PTL_CT_NONE;
  params.ign     = 0;
  params.options = PTL_ME_OP_GET | PTL_ME_EVENT_LINK_DISABLE |
                   PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_MAY_ALIGN |
                   PTL_ME_IS_ACCESSIBLE | PTL_ME_USE_ONCE;

  /* Then, post the memory entry to the CTRL RXQ. Target will execute 
   * a GET operation on this. */
  status = uct_bxi_recv_block_activate(block, &params);
  if (status != UCS_OK) {
    goto err;
  }

  /* Now, allocate a send descriptor to pack rendez-vous metadata. */
  UCT_BXI_IFACE_GET_TX_TAG_DESC_ERR(iface, &iface->tx.send_desc_mp, op, ep,
                                    comp, uct_bxi_send_comp_op_handler,
                                    status = UCS_ERR_NO_RESOURCE;
                                    goto err_release_block;);

  /* Rendez-vous operation will creates two events: 
   * - PTL_EVENT_ACK: acknowledge the reception of the first control message
   * - PTL_EVENT_GET: target GET operation has issued the GET operation and 
   *                  has retrieved the data.
   * Therefore, we increment the completion counter so that the operation is 
   * actually completed on the PTL_EVENT_GET. */
  op->comp.comp++;

  /* Attach operation to block and vice versa so they can be both released, 
   * either on completion or if the operation is canceled. */
  block->op      = op;
  op->rndv.block = block;

  /* Operation length must be eager_limit + 1 to triggered remote get in case
   * the receive has been posted early. */
  op->length = uct_bxi_pack_rndv(iface, op + 1, (uint64_t)ptl_iov->iov_base,
                                 ptl_iov->iov_len, header, header_length);

  UCT_BXI_HDR_SET(hdr, ptl_iov->iov_len, UCT_BXI_TAG_PROT_RNDV_HW);

  if (ucs_unlikely(flags & UCT_TAG_OFFLOAD_OPERATION)) {
    /* An operation context was provided, so the operation must be 
     * triggered. */
    ucs_assert(!PtlHandleIsEqual(gop->cnt.cth, PTL_INVALID_HANDLE));

    status = uct_bxi_wrap(PtlTriggeredPutNB(
            iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1), op->length,
            PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.tag, tag, 0, op, hdr,
            gop->cnt.cth, gop->cnt.threshold));
    ucs_debug("BXI: triggered rndv. nid=%u, pid=%u, size=%lu",
              ep->dev_addr.pid.phys.nid, ep->dev_addr.pid.phys.pid,
              ptl_iov->iov_len);
  } else {
    status =
            uct_bxi_wrap(PtlPutNB(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                  op->length, PTL_ACK_REQ, ep->dev_addr.pid,
                                  ep->iface_addr.tag, tag, 0, op, hdr));
  }
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut rndv zcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);
  /* Increment endpoint send counter. */
  uct_bxi_ep_tag_inc_cnt(ep);

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

  /* Overwrite completion handler. Operation must be completed only if both 
   * PTL_EVENT_ACK from rendezvous was also processed. */
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
  ptl_hdr_data_t   hdr   = 0;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_LENGTH(header_length, 0, iface->config.seg_size,
                   "tag_rndv_request");
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

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
  status = uct_bxi_wrap(PtlPutNB(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 header_length, PTL_ACK_REQ, ep->dev_addr.pid,
                                 ep->iface_addr.tag, tag, 0, op, hdr));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut rndv request return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);
  /* Increment endpoint send counter. */
  uct_bxi_ep_tag_inc_cnt(ep);

err:
  return status;
}

static UCS_F_ALWAYS_INLINE int
uct_bxi_tag_recv_is_offloaded(uct_tag_context_t *ctx)
{
  return ctx->gop != NULL;
}

static UCS_F_ALWAYS_INLINE ucs_status_t uct_bxi_iface_tag_recv_rndv_zcopy(
        uct_bxi_iface_t *iface, uct_bxi_ep_t *ep, uct_bxi_recv_block_t *block,
        uct_bxi_mem_desc_t *mem_desc, uct_bxi_block_cnt_t *cnt,
        ptl_size_t thresh)
{
  ucs_status_t             status;
  uct_bxi_iface_send_op_t *op;
  uct_tag_t                tag;

  /* If message size is lower than eager limit, there will be no rendezvous. 
   * The message will be truncated, either by BXI or by UCP.*/
  if (block->size < iface->config.tm.eager_limit) {
    return UCS_OK;
  }

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, NULL,
                               uct_bxi_recv_rndv_tag_handler, block->size);

  op->length = block->size;

  /* Counter-based tag, see Barret and al. */
  tag = UCT_BXI_BUILD_RNDV_TAG(ep->dev_addr.pid, ep->cnt->precv);

  status = uct_bxi_wrap(PtlTriggeredGetNB(
          op->mem_desc->mdh, (ptl_size_t)block->start, op->length,
          ep->dev_addr.pid, ep->iface_addr.ctrl, tag, 0, op, cnt->cth, thresh));
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlTriggeredGet request return %d", status);
  }

  return status;

err:
  ucs_mpool_put(op);
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
  uct_bxi_ep_t               *ep  = ucs_derived_of(ctx->reply_ep, uct_bxi_ep_t);
  uct_bxi_gop_t              *gop = ucs_derived_of(ctx->gop, uct_bxi_gop_t);
  uct_bxi_recv_block_t       *block;
  uct_bxi_mem_desc_t         *mem_desc;
  uct_bxi_recv_block_params_t params;

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
  UCT_BXI_IFACE_GET_RX_TAG_DESC_ERR(iface, &iface->tm.recv_block_mp, block,
                                    iface->rx.tag.q, ptl_iov->iov_base,
                                    ptl_iov->iov_len, tag, ctx,
                                    status = UCS_ERR_EXCEEDS_LIMIT;
                                    goto err_remove_hash);

  /* Decide wether to offload the rendezvous or not. */
  if (ucs_unlikely(uct_bxi_tag_recv_is_offloaded(ctx))) {
    if (block->size > iface->config.tm.eager_limit && ep != NULL) {
      /* If operations is offloaded, we need to count the completion of the 
       * PtlTriggeredGet and we do so by creating a dedicated MD. */
      mem_desc = uct_bxi_md_mem_desc_create_inline(uct_bxi_iface_md(iface),
                                                   iface->tx.eqh, gop->cnt.cth);
      if (mem_desc == NULL) {
        goto err_release_block;
      }

      /* In this case, use the generic operation provided in the tag context. */
      //NOTE: offloaded are now used only within the collective context so we
      //      may rely on the size condition since send and receive size must be
      //      equal. In this case, we don't use bytes.
      //FIXME: If previous condition is relaxed, then threshold configuration
      //       becomes undecidable. CT_BYTES has to be used to enable offloaded
      //       rendezvous and we have no way to decide why threshold to use for
      //       the next operation.
      status = uct_bxi_iface_tag_recv_rndv_zcopy(
              iface, ep, block, mem_desc, &gop->cnt, gop->cnt.threshold + 1);
      if (status != UCS_OK) {
        uct_bxi_md_mem_desc_fini(mem_desc);
        goto err_release_block;
      }
    }

    /* Set param for ME Append. */
    params.cth     = gop->cnt.cth;
    params.options = UCT_BXI_ME_OPT_RECV_ZCOPY_CNT;

    block->flags |= UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOAD;
    /* Save counter handle in case receive is cancelled. */
    block->cth = block->cnt.cth;
  } else {
    if (block->size > iface->config.tm.eager_limit && ep != NULL) {
      /* In this case, use the block counter. */
      status = uct_bxi_iface_tag_recv_rndv_zcopy(
              iface, ep, block, iface->tx.mem_desc, &block->cnt,
              block->cnt.threshold + iface->config.tm.eager_limit + 1);

      /* Set param for ME Append. */
      params.cth     = block->cnt.cth;
      params.options = UCT_BXI_ME_OPT_RECV_ZCOPY_CNT_BYTES;

      block->flags |= UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOAD |
                      UCT_BXI_RECV_BLOCK_FLAG_UPDATE_CNT;
      /* Save counter in case receive is cancelled. */
      block->cth = block->cnt.cth;
    } else {
      params.cth     = PTL_CT_NONE;
      params.options = UCT_BXI_ME_OPT_RECV_ZCOPY;
    }
  }

  params.start = ptl_iov->iov_base;
  params.size  = ptl_iov->iov_len;
  params.match = tag;
  params.ign   = ~tag_mask;

  /* Then, post the memory entry. */
  status = uct_bxi_recv_block_activate(block, &params);
  if (status != UCS_OK) {
    goto err_release_op;
  }

  /* Increment Posted receive counter */
  uct_bxi_ep_inc_precv(ep);

  *(uct_bxi_recv_block_t **)ctx->priv = block;

  return status;

err_release_op:
  ucs_mpool_put(block->op);
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
  if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOAD) {
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

ucs_status_t uct_bxi_iface_tag_gop_create(uct_iface_h tl_iface,
                                          uct_gop_h  *gop_p)
{
  ucs_status_t     status = UCS_OK;
  uct_bxi_gop_t   *gop;
  uct_bxi_iface_t *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);

  gop = ucs_mpool_get(&iface->tm.gop_mp);
  if (gop == NULL) {
    status = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  gop->block = NULL;

  *gop_p = (uct_gop_h)gop;

  return status;

err_free_gop:
  ucs_mpool_put(gop);
err:
  return status;
}

void uct_bxi_iface_tag_gop_delete(uct_iface_h tl_iface, uct_gop_h tl_gop)
{
  uct_bxi_gop_t *gop = ucs_derived_of(tl_gop, uct_bxi_gop_t);

  ucs_mpool_put(gop);
}

ucs_status_t uct_bxi_iface_tag_gop_depends_on(uct_iface_h tl_iface,
                                              uct_gop_h   tl_gop,
                                              uct_gop_h  *tl_gops,
                                              size_t      gop_cnt)
{
  ucs_status_t   status = UCS_OK;
  uct_bxi_gop_t *gop    = ucs_derived_of(tl_gop, uct_bxi_gop_t);
  uct_bxi_gop_t *tmp_gop;
  size_t         i;

  /* To call this, we must have at least on dependency. */
  ucs_assert(gop_cnt >= 1);

  for (i = 0; i < gop_cnt; i++) {
    tmp_gop = ucs_derived_of(tl_gops[i], uct_bxi_gop_t);

    ucs_assert(!PtlHandleIsEqual(tmp_gop->cnt.cth, PTL_INVALID_HANDLE));

    status = uct_bxi_wrap(
            PtlTriggeredCTIncNB(gop->cnt.cth, (ptl_ct_event_t){1, 0},
                                tmp_gop->cnt.cth, tmp_gop->cnt.threshold));
    if (status != UCS_OK) {
      ucs_fatal("BXI: failed setting trig inc.");
    }
    gop->cnt.threshold++;
  }

  return status;
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

  status = uct_bxi_wrap(PtlAtomicNB(
          iface->tx.mem_desc->mdh, (uint64_t)&op->atomic.value, size,
          PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.rma, 0, remote_addr, op,
          0, uct_bxi_atomic_op_table[opcode], dt));

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

  status = uct_bxi_wrap(PtlFetchAtomicNB(
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

  status = uct_bxi_wrap(
          PtlSwapNB(iface->tx.mem_desc->mdh, (uint64_t)result,
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

  if (uct_bxi_iface_available(iface) > 0 &&
      ((iface->tm.enabled && !ucs_mpool_is_empty(&iface->tm.recv_block_mp)) ||
       !iface->tm.enabled)) {
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
