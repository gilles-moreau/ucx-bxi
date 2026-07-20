#include "bxi_ep.h"
#include "bxi_iface.h"
#include "bxi_log.h"
#include "bxi_rxq.h"
#include "ucs/memory/memory_type.h"

#include <sys/types.h>
#include <time.h>
#include <ucs/algorithm/crc.h>
#include <ucs/profile/profile.h>
#include <uct/base/uct_log.h>

//NOTE: No overflow event needs to be handled since the message will either:
//      - generate a PTL_EVENT_PUT in a block in the overflow list, block will
//      then be cancelled/unlinked, or
//      - generate a PTL_EVENT_PUT in the priority list.
#define UCT_BXI_ME_OPT_RECV_ZCOPY                                              \
  PTL_ME_OP_PUT | PTL_ME_USE_ONCE | PTL_ME_EVENT_LINK_DISABLE |                \
          PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_EVENT_OVER_DISABLE

#define UCT_BXI_CT_INC (ptl_ct_event_t){.success = 1, .failure = 0}

static UCS_F_ALWAYS_INLINE ucs_memory_type_t
uct_bxi_get_memory_type(uct_mem_h mem)
{
#ifdef HAVE_GDR_COPY
  return ((void *)mem == (void *)0xdeadbeef) || (mem == NULL) ?
                 UCS_MEMORY_TYPE_HOST :
                 UCS_MEMORY_TYPE_CUDA;
#else
  ucs_assert((void *)mem == (void *)0xdeadbeef);
  return UCS_MEMORY_TYPE_HOST;
#endif
}

/* Callback of receiver for rendezvous protocol. */
static void uct_bxi_recv_rndv_tag_handler(uct_bxi_iface_send_op_t *op,
                                          const void              *resp)
{
  uct_bxi_recv_block_t *block = op->rndv.block;

  /* Whether rendezvous was offloaded or not, handler is called after the 
   * completion of GET which is always performed on MD with counter,  so 
   * corresponding sw counter must be incremented. */
  uct_bxi_recv_block_update_cnt(block);

  if (op->flags & UCT_BXI_IFACE_SEND_OP_FLAG_COMPLETED) {
    return;
  }

  /* Invoke tag-related callback. */
  block->ctx->completed_cb(
          block->ctx, block->stag, 0, block->send_size, NULL,
          block->size < block->send_size ? UCS_ERR_MESSAGE_TRUNCATED : UCS_OK);

  uct_bxi_recv_block_release(block);

  //NOTE: op was not placed in the ep send queue.
}

static ucs_status_t uct_bxi_iface_block_handle_rndv(uct_bxi_iface_t      *iface,
                                                    uct_bxi_conn_t       *conn,
                                                    uct_bxi_recv_block_t *block,
                                                    uct_bxi_conn_ooo_t   *ooo)
{
  /* Block was posted during rendez-vous. Event means target has successfully
   * read data, initiator's operation can thus be completed. Block is released 
   * in uct_bxi_send_op_rndv_handler. */
  uct_bxi_iface_completion_op(block->op);

  return UCS_OK;
}

static void uct_bxi_send_op_rndv_handler(uct_bxi_iface_send_op_t *op,
                                         const void              *resp)
{
  /* Cancelled operation means target matched request in software only, 
   * thus rendezvous sw protocol is performed instead. Upper layer has 
   * thus cancelled rndv send and its block will never be matched, so 
   * deactivate it. */
  if (op->flags & UCT_BXI_IFACE_SEND_OP_FLAG_CANCELLED) {
    uct_bxi_recv_block_deactivate(op->rndv.block);
    goto release_block;
  }

  if (op->user_comp != NULL) {
    uct_invoke_completion(op->user_comp, UCS_OK);
  }

release_block:
  uct_bxi_recv_block_release(op->rndv.block);
  uct_bxi_ep_remove_from_queue(op);
}

ucs_status_t uct_bxi_ep_tag_eager_short(uct_ep_h tl_ep, uct_tag_t tag,
                                        const void *data, size_t length)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  ptl_hdr_data_t   hdr;
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  //NOTE: use length > 0 to pass UCT_SKIP_ZERO_LENGTH test. 0 length messages
  //      are allowed, for example barrier messages.
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, NULL,
                               uct_bxi_send_op_handler, 1);

  UCT_BXI_TAG_HDR_SET(hdr, UCT_BXI_TAG_ID_RNDV_HW, length, ep->conn);
  ep->conn->sn++;
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)data,
                               length, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.tag, tag, 0, op, hdr));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut short return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
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
  ptl_hdr_data_t           hdr;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Right now, imm is used by UCP only for sync protocol by setting imm to 
   * the address of the local endpoint. But we need ptl hdr to add ordering 
   * metadata so we do not support it. */
  ucs_assert(imm == 0);
  UCT_BXI_TAG_HDR_SET(hdr, UCT_BXI_TAG_ID_EAGER, size, ep->conn);
  ep->conn->sn++;

  if (ucs_unlikely(flags & UCT_TAG_SCHEDULE)) {
    gop  = arg;
    size = gop->super.size;

    UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, NULL,
                                 uct_bxi_send_op_handler, 0);

    status = uct_bxi_wrap(PtlTriggeredPut(
            iface->tx.mem_desc->mdh, (ptl_size_t)(gop + 1), size, PTL_ACK_REQ,
            ep->dev_addr.pid, ep->iface_addr.tag, tag, 0, op, hdr, gop->cth,
            gop->ct_value));
  } else {
    /* Take a bcopy send descriptor from the memory pool. Descriptor has 
     * an operation first, then a buffer of size seg_size. */
    UCT_BXI_IFACE_GET_TX_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                    pack_cb, arg, uct_bxi_send_op_handler,
                                    &size);
    if (size < 0) {
      goto err;
    }

    status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 size, PTL_ACK_REQ, ep->dev_addr.pid,
                                 ep->iface_addr.tag, tag, 0, op, hdr));
  }

  if (status == UCS_ERR_NO_RESOURCE) {
    size = UCS_ERR_NO_RESOURCE;
    goto err_release_op;
  } else if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, TAG, BCOPY, size);
  uct_bxi_log_put(iface);

  return size;

err_release_op:
  ucs_mpool_put(op);
err:
  return size;
}

static UCS_F_ALWAYS_INLINE ucs_status_t uct_bxi_ep_tag_zcopy_op(
        uct_bxi_iface_t *iface, uct_bxi_ep_t *ep, uct_tag_t tag, uint64_t imm,
        unsigned flags, const uct_iov_t *iov, size_t iovcnt,
        uct_completion_t *comp, uct_bxi_iface_send_op_t **op_p)
{
  ucs_status_t             status;
  ptl_iovec_t             *ptl_iov;
  uct_bxi_gop_t           *gop = ucs_derived_of(comp->gop, uct_bxi_gop_t);
  uct_bxi_iface_send_op_t *op;
  ptl_hdr_data_t           hdr;

  UCT_BXI_IFACE_GET_TX_OP_COMP_ERR(iface, &iface->tx.send_op_mp, op, ep, comp,
                                   uct_bxi_send_op_handler,
                                   status = UCS_ERR_NO_RESOURCE;
                                   goto err);

  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  UCT_BXI_TAG_HDR_SET(hdr, UCT_BXI_TAG_ID_EAGER, iov->length, ep->conn);
  ep->conn->sn++;
  if (ucs_unlikely(flags & UCT_TAG_SCHEDULE)) {
    status = uct_bxi_wrap(PtlTriggeredPut(
            iface->tx.mem_desc->mdh, (ptl_size_t)ptl_iov->iov_base,
            ptl_iov->iov_len, PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.tag,
            tag, 0, op, hdr, gop->cth, gop->ct_value));
  } else {
    status = uct_bxi_wrap(
            PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)ptl_iov->iov_base,
                   ptl_iov->iov_len, PTL_ACK_REQ, ep->dev_addr.pid,
                   ep->iface_addr.tag, tag, 0, op, hdr));
  }

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut zcopy return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);

err:
  return status;
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
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_ep_get_zcopy");
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Right now, imm is used by UCP only for sync protocol by setting imm to 
   * the address of the local endpoint. But we need ptl hdr to add ordering 
   * metadata so we do not support it. */
  ucs_assert(imm == 0);

  status = uct_bxi_ep_tag_zcopy_op(iface, ep, tag, imm, flags, iov, iovcnt,
                                   comp, &op);
  if (status != UCS_INPROGRESS) {
    goto err;
  }

  UCT_TL_EP_STAT_OP(&ep->super, TAG, ZCOPY, uct_iov_total_length(iov, iovcnt));
  uct_bxi_log_put(iface);

err:
  return status;
}

static UCS_F_ALWAYS_INLINE size_t uct_bxi_pack_rndv(
        uct_bxi_iface_t *iface, void *dest, void *src, size_t length,
        uct_bxi_mem_t *memh, const void *header, unsigned header_length)
{
  uct_md_mkey_pack_params_t params = {.flags = 0};
  uct_bxi_hdr_rndv_t       *hdr =
          UCS_PTR_BYTE_OFFSET(dest, iface->tm.rndv_hdr_offset);

  /* Only copy data for host memory. For cuda memory, gdrcopy will be used 
   * which will increase latency and also decrease potential for overlap. */
  //TODO: For GPU compatibility and performance, we do not copy part of the
  //      buffer anymore, see uct_bxi_iface_tag_recv_rndv_zcopy. This is a waste
  //      of bandwidth since we still have to send eager_size + 1 of data to
  //      trigger the remote get...
  //      Maybe think for copying the data from GPU to CPU with gdrcopy.

  //if (memh == (void *)UCS_MEMORY_TYPE_HOST) {
  //  /* First copy the payload up to buffer capacity minus size required for the
  //   * rndv hdr and the user header. */
  //  memcpy(dest, src, ucs_min(length, iface->tm.rndv_hdr_offset));
  //}

  hdr->remote_addr   = (uint64_t)src;
  hdr->header_length = header_length;
  uct_bxi_mkey_pack(iface->super.md, memh, NULL, PTL_SIZE_MAX, &params,
                    hdr->rkey);

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
  ssize_t                  size;

  UCT_BXI_CHECK_EP_PTR(ep);
  UCT_BXI_CHECK_RNDV_DATA(iovcnt, (unsigned long)iface->config.max_iovecs,
                          iov->length, iface->config.max_msg_size);
  UCT_BXI_CHECK_IFACE_RES_PTR(iface, ep);

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  //TODO: remove ptl_iovec but explicitly show buffer resolution in case
  //      of GPU memory
  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  /* First, allocate a TAG block from the memory pool. Receive block is 
   * used to match the remote GET operation and is posted to the CTRL RXQ. 
   * Reduce it off of the eager size that will be sent. */
  UCT_BXI_IFACE_GET_RX_RNDV_DESC(
          iface, &iface->tm.recv_block_mp, block, mem_type, ptl_iov->iov_base,
          ptl_iov->iov_len, iface->rx.ctrl.q->pti, ep->conn->id.conn_key,
          ep->conn->send, uct_bxi_iface_block_handle_rndv,
          status = UCS_ERR_NO_RESOURCE;
          goto err);

  me.start             = block->start;
  me.length            = block->size;
  me.match_bits        = block->tag;
  me.match_id.phys.nid = ep->dev_addr.pid.phys.nid;
  me.match_id.phys.pid = ep->dev_addr.pid.phys.pid;
  me.uid               = PTL_UID_ANY;
  me.ct_handle         = PTL_CT_NONE;
  me.ignore_bits       = 0;
  me.options = PTL_ME_OP_GET | PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_MAY_ALIGN |
               PTL_ME_IS_ACCESSIBLE | PTL_ME_USE_ONCE;

  /* Then, post the memory entry to the CTRL RXQ. Target will execute 
   * a GET operation on this. */
  //TODO: To make sure remote get will for sure match this ME, we should
  //      wait for PTL_EVENT_LINK before sending the control message. In
  //      current workload, this never happened yet.
  status = uct_bxi_recv_block_exp_activate(iface->rx.ctrl.q, block, &me);
  if (status != UCS_OK) {
    goto err_release_block;
  }

  /* Now, allocate a send descriptor and pack rendez-vous metadata. */
  UCT_BXI_IFACE_GET_TX_TAG_BCOPY_DESC_ERR(
          iface, &iface->tx.send_desc_mp, op, ep, comp,
          uct_bxi_send_op_rndv_handler, uct_bxi_pack_rndv, iov->buffer,
          ptl_iov->iov_len, iov->memh, header, header_length, &size,
          status = UCS_ERR_NO_RESOURCE;
          goto err_deactivate_block);

  /* Rendez-vous operation will creates two events: 
   * - PTL_EVENT_ACK: acknowledge the reception of the first control message
   * - PTL_EVENT_GET/rndv cancel: target has issued the GET operation and 
   *   has retrieved the data or control message was received as unexpected, 
   *   thus initiator rendezvous will be cancelled during ATS or FIN.
   *   */
  op->comp.comp++;

  /* Attach operation to block and vice versa so they can be both released, 
   * either on PTL_EVENT_GET completion or if the operation is canceled. */
  block->op      = op;
  op->rndv.block = block;

  ucs_debug("BXI: send block. start=%lu, length=%lu, send tag=0x%016lx, "
            "tag=0x%016lx, nid=%u, pid=%u, op=%p, pti=%d, conn key=%d",
            (uint64_t)block->start, block->size, tag, block->tag,
            uct_bxi_iface_md(iface)->pid.phys.nid,
            uct_bxi_iface_md(iface)->pid.phys.pid, op, iface->rx.ctrl.q->pti,
            ep->conn->id.conn_key);

  ucs_assert(ptl_iov->iov_len <= UCT_BXI_TAG_LENGTH_MAX);
  UCT_BXI_TAG_HDR_SET(hdr, UCT_BXI_TAG_ID_RNDV_HW, ptl_iov->iov_len, ep->conn);
  ep->conn->sn++;

  if (ucs_unlikely(flags & UCT_TAG_SCHEDULE)) {
    ucs_assert(gop != NULL);
    ucs_assert(!PtlHandleIsEqual(gop->cth, PTL_INVALID_HANDLE));

    status = uct_bxi_wrap(
            PtlTriggeredPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1), size,
                            PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.tag,
                            tag, 0, op, hdr, gop->cth, gop->ct_value));
  } else {
    //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
    status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 size, PTL_ACK_REQ, ep->dev_addr.pid,
                                 ep->iface_addr.tag, tag, 0, op, hdr));
  }
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut rndv zcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);
  /* Increment rndv send counter. */
  uct_bxi_rndv_inc_send_cnt(iface, ep->conn);

out:

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

  op->flags |= UCT_BXI_IFACE_SEND_OP_FLAG_CANCELLED;

  // NOTE: Uncertain if PTL_EVENT_ACK from the rendezvous message has
  //       been processed, so we can't return the operation to the pool.
  //       User completion callback will not be called, see
  //       uct_bxi_send_op_rndv_handler.
  uct_bxi_iface_completion_op(op);

  return UCS_OK;
}

static UCS_F_ALWAYS_INLINE size_t uct_bxi_pack_rndv_request(
        uct_bxi_iface_t *iface, void *dest, void *src, size_t length,
        ucs_memory_type_t mem_type, const void *header, unsigned header_length)
{
  memcpy(dest, header, header_length);
  return header_length;
}

ucs_status_t uct_bxi_ep_tag_rndv_request(uct_ep_h tl_ep, uct_tag_t tag,
                                         const void *header,
                                         unsigned header_length, unsigned flags)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;
  ssize_t                  size;
  ptl_hdr_data_t           hdr;

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
  UCT_BXI_IFACE_GET_TX_TAG_BCOPY_DESC_ERR(
          iface, &iface->tx.send_desc_mp, op, ep, NULL, uct_bxi_send_op_handler,
          uct_bxi_pack_rndv_request, NULL, 0, UCS_MEMORY_TYPE_UNKNOWN, header,
          header_length, &size, status = UCS_ERR_NO_RESOURCE;
          goto err);

  UCT_BXI_TAG_HDR_SET(hdr, UCT_BXI_TAG_ID_RNDV_SW, 0, ep->conn);
  ep->conn->sn++;
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               size, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.tag, tag, 0, op, hdr));

  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut rndv request return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);

err:
  return status;
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_iface_block_init_trigget(uct_bxi_iface_t *iface, uct_bxi_ep_t *ep,
                                 uct_bxi_recv_block_t *block, ptl_me_t *me,
                                 unsigned flags)
{
  ucs_status_t     status = UCS_OK;
  ptl_match_bits_t tag;

  /* There are three main cases for the triggered get:
   * - No offloaded rendez-vous, no schedule => no counters.
   * - Offloaded rendez-vous => with counters, counted by bytes to handle 
   *   eager send and rendez-vous recv (mpi standard). 
   *   Rendez-vous is offloaded only if size > eager_limit.
   *   UCT_TAG_RECV_REPLY_EP must be set.
   * - Schedule => with counters, counted by event. UCT_TAG_SCHEDULE must 
   *   be set. Rendez-vous is offloaded iff UCT_TAG_RECV_RNDV. 
   *   UCT_TAG_RECV_REPLY_EP and UCT_TAG_SCHEDULE must be set as well.
   **/

  if (flags & (UCT_TAG_SCHEDULE | UCT_TAG_RECV_RNDV)) {
    /* Counter is needed. */
    block->flags |= UCT_BXI_RECV_BLOCK_FLAG_COUNTER_ENABLED;
    /* Update ME parameters. */
    me->ct_handle  = block->cth;
    me->options   |= PTL_ME_EVENT_CT_COMM | PTL_ME_EVENT_CT_OVERFLOW;

    if (flags & UCT_TAG_RECV_RNDV) {
      ucs_assert(flags & UCT_TAG_RECV_REPLY_EP);
      ucs_assert(ep != NULL);
      block->flags |= UCT_BXI_RECV_BLOCK_FLAG_RNDV |
                      UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOADED |
                      UCT_BXI_RECV_BLOCK_FLAG_INCREMENTED;

      block->op->length = block->size;
      UCT_BXI_RNDV_TAG_SET(tag, ep->iface_addr.ctrl, ep->conn->id.conn_key,
                           ep->conn->recv);

      //TODO: think about adding the operation to the send queue of the endpoint.
      //      Problem rn is that this cannot be supported without reply_ep.
      //      Except if we put the send queue to the conn structure?
      status = uct_bxi_wrap(PtlTriggeredGet(
              block->mdh, (ptl_size_t)block->start, block->op->length,
              ep->dev_addr.pid, ep->iface_addr.ctrl, tag, 0, block->op,
              block->cth, block->ct_value + 1));
      if (status != UCS_OK) {
        ucs_fatal("BXI: PtlTriggeredGet request return %d", status);
      }

      ucs_debug(
              "BXI: recv trig get. ep=%p, start=%lu, length=%lu, tag=0x%016lx, "
              "nid=%u, pid=%u, pti=%d, conn_key=%d, op=%p, recv block=%p, ct "
              "value=%lu",
              ep, (ptl_size_t)block->start, block->op->length, tag,
              ep->dev_addr.pid.phys.nid, ep->dev_addr.pid.phys.pid,
              ep->iface_addr.ctrl, ep->conn->id.conn_key, block->op, block,
              block->ct_value);

      /* Increment rndv receive counter. */
      uct_bxi_rndv_inc_recv_cnt(iface, ep->conn);
    }
  } else {
    me->ct_handle = PTL_CT_NONE;
  }
}

//TODO: better handler receive completion mecanisms. It's a mess right now.
//TODO: improve logic. Support for both offloaded and non-offloaded rndv
//      make the implementation complicated.
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

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  /* The same tag cannot be associated to the same buffer. */
  //TODO: this is true for InfiniBand, but to be verified for Portals4.
  status = uct_bxi_iface_tag_add_to_hash(iface, ptl_iov->iov_base);
  if (status != UCS_OK) {
    goto err;
  }

  /* First, allocate a TAG block from the memory pool. */
  //NOTE: iov length may be 0 and thus we loose the buffer address when filling
  //      the ptl_iov. Block buffer is thus set using iov->buffer instead of
  //      ptl_iov.
  UCT_BXI_IFACE_GET_RX_DESC(iface, &iface->tm.recv_block_mp, block,
                            uct_bxi_get_memory_type(iov->memh), iov->buffer,
                            ptl_iov->iov_base, ptl_iov->iov_len, tag, ctx,
                            uct_bxi_iface_block_handle_tag_exp,
                            status = UCS_ERR_EXCEEDS_LIMIT;
                            goto err_remove_hash);

  if (uct_bxi_iface_has_tx_resources(iface) <= 0) {
    status = UCS_ERR_NO_RESOURCE;
    goto err_release_block;
  }

  /* An operation is needed in case a rendezvous message is received, because the
   * rendezvous threshold is configurable at runtime, we always need to allocate it.
   * Here are the possible paths:
   * - wrong prediction and eager msg was received instead, then the operation 
   *   is not used and just released before block release,
   * - endpoint was not provided, thus the operation is used to complete the 
   *   protocol upon PTL_EVENT_PUT handling, 
   * - otherwise, operation will be triggered. */
  UCT_BXI_IFACE_GET_TX_OP_COMP_ERR(iface, &iface->tx.send_op_mp, block->op, ep,
                                   NULL, uct_bxi_recv_rndv_tag_handler,
                                   status = UCS_ERR_NO_RESOURCE;
                                   goto err_release_block);
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
  block->op->rndv.block = block;

  /* Initialise ME params with default value, they may be changed during 
   * protocol configuration below. For eager message and without scheduling
   * handle, no counter is needed on the ME. */
  me.ct_handle         = PTL_CT_NONE;
  me.options           = UCT_BXI_ME_OPT_RECV_ZCOPY;
  me.match_id.phys.nid = PTL_NID_ANY;
  me.match_id.phys.pid = PTL_PID_ANY;
  me.uid               = PTL_UID_ANY;

  /* Set portals counter according to flags. */
  uct_bxi_iface_block_init_trigget(iface, ep, block, &me, ctx->flags);

  me.start       = block->start;
  me.length      = block->size;
  me.match_bits  = tag;
  me.ignore_bits = ~tag_mask;

  /* Then, post the memory entry. */
  status = uct_bxi_recv_block_exp_activate(iface->rx.tag.q, block, &me);
  if (status != UCS_OK) {
    goto err_release_op;
  }

  /* Update interface available resources. */
  uct_bxi_iface_op_res(iface, block->op);

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
  ucs_status_t          status = UCS_OK;
  uct_bxi_recv_block_t *block  = *(uct_bxi_recv_block_t **)ctx->priv;
  uct_bxi_iface_t      *iface  = ucs_derived_of(tl_iface, uct_bxi_iface_t);
  uct_bxi_conn_id_t     cid    = {0};
  uct_bxi_conn_t       *conn   = NULL;
  ptl_match_bits_t      tag;

  /* Must be removed for both eager and rndv requests. */
  uct_bxi_iface_tag_del_from_hash(iface, block->start);

  if (mode & UCT_TAG_CANCEL_MATCHED) {
    /* Posted receive was matched in overflow list, unexpected header was then 
     * consumed and ME unlinked already. Event data was cached in the interface 
     * to be retrieved now. */
    ucs_assert(iface->tm.unexp_ooo != NULL);

    if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_COUNTER_ENABLED) {
      uct_bxi_recv_block_update_cnt(block);
    }

    if (uct_bxi_iface_is_rndv_hw(iface, iface->tm.unexp_ooo)) {

      if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_INCREMENTED) {
        ucs_assert(block->op->ep != NULL);
        /* Rendezvous has been offloaded and unexpected handler called, thus 
         * rndv recv counter incremented twice. Decrement it. */
        uct_bxi_rndv_dec_recv_cnt(iface, block->op->ep->conn);
      }

      /* Save stag and send size for rndv completion, see 
       * uct_bxi_recv_rndv_tag_handler. */
      block->send_size = UCT_BXI_TAG_LENGTH_GET(iface->tm.unexp_ooo->hdr_data);
      block->stag      = iface->tm.unexp_ooo->match_bits;

      //TODO: GPU/CPU compatibility, see uct_bxi_pack_rndv
      //if (block->mem_type == UCS_MEMORY_TYPE_HOST) {
      //  /* Copy the first eager part that was sent on the first message of the
      //   * protocol and which was received in the overflow block.
      //   * Only copy for host memory. */
      //  memcpy(block->start, iface->tm.unexp_ev->start,
      //         iface->tm.rndv_hdr_offset);
      //}

      if (!(block->flags & UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOADED)) {

        cid.pid      = iface->tm.unexp_ooo->initiator;
        cid.pti      = UCT_BXI_CONN_PTI_GET(iface->tm.unexp_ooo->hdr_data);
        cid.conn_key = UCT_BXI_CONN_KEY_GET(iface->tm.unexp_ooo->hdr_data);
        /* Rendezvous was not offloaded during receive call, thus rndv recv 
         * counter not incremented, increment it now. */
        conn = uct_bxi_conn_get(iface, &cid);
        ucs_assert(conn != NULL);

        //NOTE: counter was incremented during unexpected handler already, so
        //      decrement by one to create the correct tag.
        UCT_BXI_RNDV_TAG_SET(tag, cid.pti, cid.conn_key, conn->recv - 1);

        /* Rendezvous was not offloaded although sender sent a hw rndv request.
         * Complete the rendezvous. */
        uct_bxi_iface_complete_rndv(iface, block, iface->tm.unexp_ooo->hdr_data,
                                    tag, iface->tm.unexp_ooo->initiator,
                                    block->send_size);
      }

      /* Block and operation will be released in operation handler. */
      uct_bxi_iface_completion_op(block->op);

      /* Resources will be release during PTL_EVENT_REPLY. */
      status = UCS_INPROGRESS;
      /* Reset to NULL to let uct_bxi_iface_block_handle_tag_unexp know the ME 
       * do not need to be consumed. */
      iface->tm.unexp_ooo = NULL;
      goto out;

    } else {
      /* Either unexpected sw rndv or eager. */
      if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOADED) {
        ucs_assert(block->op->ep != NULL);
        uct_bxi_recv_block_cancel_triggered(block);
        uct_bxi_rndv_dec_recv_cnt(iface, block->op->ep->conn);
      }
      /* Reset to NULL to let uct_bxi_iface_block_handle_tag_unexp know the ME 
       * do not need to be consumed. */
      iface->tm.unexp_ooo = NULL;
    }
  } else {
    /* Cancellation was issued from ucp_request_cancel control flow, meaning ME 
     * remains and must be unlinked from the hw. */
    uct_bxi_recv_block_deactivate(block);
  }

  if (!(mode & UCT_TAG_CANCEL_FORCE)) {
    block->ctx->completed_cb(block->ctx, block->tag, 0, block->size, NULL,
                             UCS_ERR_CANCELED);
  }

  uct_bxi_iface_release_op(block->op);
  uct_bxi_recv_block_release(block);

out:
  return status;
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

  ucs_assert(block->flags & UCT_BXI_RECV_BLOCK_FLAG_COUNTER_ENABLED);

  gop = ucs_mpool_get(&iface->tm.gop_mp);
  if (gop == NULL) {
    ucs_debug("BXI: no more counter");
    status = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_RNDV) {
    /* thresh = current counter value + 1 (first match) + 1 (get) */
    thresh = block->ct_value + 2;
  } else {
    thresh = block->ct_value + 1;
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

ucs_status_t uct_bxi_ep_config_key(uct_ep_h uct_ep, uct_ep_conn_key_t conn_key)
{
  ucs_status_t      status = UCS_OK;
  uct_bxi_ep_t     *ep     = ucs_derived_of(uct_ep, uct_bxi_ep_t);
  uct_bxi_iface_t  *iface  = ucs_derived_of(uct_ep->iface, uct_bxi_iface_t);
  uct_bxi_conn_id_t id     = {0};

  /* Should only be called in tag-matching datapath. */
  ucs_assert(iface->tm.enabled);

  /* Since counters must be local to each UCT endpoint, connection match 
   * need to be based on the triplet: Portals PID, local Portals Table Index and 
   * Connection Key. */
  id.pid      = ep->dev_addr.pid;
  id.pti      = iface->rx.ctrl.q->pti;
  id.conn_key = conn_key & UCT_BXI_CONN_KEY_MASK;

  /* Get base endpoint counter based on triplet. */
  ep->conn = uct_bxi_conn_get(iface, &id);
  if (ep->conn == NULL) {
    status = uct_bxi_conn_create(iface, id, &ep->conn);
  }

err:
  return status;
}
