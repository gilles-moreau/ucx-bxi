#include "bxi_ep.h"
#include "bxi_iface.h"
#include "bxi_log.h"

#include <sys/types.h>
#include <time.h>
#include <ucs/algorithm/crc.h>
#include <ucs/profile/profile.h>
#include <uct/base/uct_log.h>

ptl_op_t uct_bxi_atomic_op_table[] = {
        [UCT_ATOMIC_OP_ADD] = PTL_SUM,   [UCT_ATOMIC_OP_AND] = PTL_BAND,
        [UCT_ATOMIC_OP_OR] = PTL_BOR,    [UCT_ATOMIC_OP_XOR] = PTL_BXOR,
        [UCT_ATOMIC_OP_SWAP] = PTL_SWAP, [UCT_ATOMIC_OP_CSWAP] = PTL_CSWAP,
};

static ucs_status_t uct_bxi_ep_execute_op(uct_bxi_iface_t         *iface,
                                          uct_bxi_ep_t            *ep,
                                          uct_bxi_iface_send_op_t *op);

// Operation completion handlers
void uct_bxi_send_op_handler(uct_bxi_iface_send_op_t *op, const void *resp)
{
  if (op->user_comp != NULL) {
    uct_invoke_completion(op->user_comp, UCS_OK);
  }

  uct_bxi_ep_remove_from_queue(op);
}

static void uct_bxi_ep_get_bcopy_handler(uct_bxi_iface_send_op_t *op,
                                         const void              *resp)
{
  op->get.unpack_cb(op->get.unpack_arg, resp, op->length);

  if (op->user_comp != NULL) {
    uct_invoke_completion(op->user_comp, UCS_OK);
  }

  uct_bxi_ep_remove_from_queue(op);
}

static void uct_bxi_send_ato_op_handler(uct_bxi_iface_send_op_t *op,
                                        const void              *resp)
{
  if (uct_bxi_ep_is_intra_node(op->ep)) {
    PtlAtomicSync();
  }

  if (op->user_comp) {
    uct_invoke_completion(op->user_comp, UCS_OK);
  }

  uct_bxi_ep_remove_from_queue(op);
}

static void uct_bxi_ep_flush_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                             const void              *resp)
{
  uct_bxi_iface_send_op_t *tmp, *fop;

  //NOTE: flush operation are only used when a user_comp is provided
  if (op->flags & UCT_BXI_IFACE_SEND_OP_FLAG_FLUSH) {
    uct_invoke_completion(op->user_comp, UCS_OK);
  } else {
    ucs_assert(op->flags & UCT_BXI_IFACE_SEND_OP_FLAG_FENCE);
    /* Decrement endpoint fence beat */
    op->ep->fence_beat--;
    /* Loop over fenced operations on endpoint and complete them if possible. */
    ucs_list_for_each_safe (fop, tmp, &op->ep->send_ops, elem) {
      if (fop->flags & (UCT_BXI_IFACE_SEND_OP_FLAG_FENCE |
                        UCT_BXI_IFACE_SEND_OP_FLAG_FLUSH)) {
        continue;
      }

      fop->ep_fb--;
      ucs_assert(fop->ep_fb >= 0);
      ucs_assert(fop->flags & UCT_BXI_IFACE_SEND_OP_FLAG_FENCED);
      uct_bxi_ep_execute_op(fop->iface, fop->ep, fop);
    }
  }

  uct_bxi_ep_remove_from_queue(op);
}

static ucs_status_t uct_bxi_ep_execute_op(uct_bxi_iface_t         *iface,
                                          uct_bxi_ep_t            *ep,
                                          uct_bxi_iface_send_op_t *op)
{
  ucs_status_t status;

  /* Check if operation can be executed. If fence beat > 0, it means a 
   * fence operation is still ongoing and operation must be stalled until 
   * its completion. */
  if (op->ep_fb > 0) {
    op->flags |= UCT_BXI_IFACE_SEND_OP_FLAG_FENCED;
    status     = UCS_OK;
    goto out;
  };

  switch (op->flags & UCT_BXI_IFACE_SEND_OP_MASK) {
  case UCT_BXI_IFACE_SEND_OP_TYPE_AM:
    status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 op->length, PTL_ACK_REQ, ep->dev_addr.pid,
                                 ep->iface_addr.am, 0, 0, op, op->am.hdr));
    break;
  case UCT_BXI_IFACE_SEND_OP_TYPE_PUT_ZCOPY:
    status = uct_bxi_wrap(
            PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)op->put.buffer,
                   op->length, PTL_ACK_REQ, ep->dev_addr.pid,
                   ep->iface_addr.rma, 0, op->put.resolved_raddr, op, 0));
    break;
  case UCT_BXI_IFACE_SEND_OP_TYPE_PUT_BCOPY:
    status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 op->length, PTL_ACK_REQ, ep->dev_addr.pid,
                                 ep->iface_addr.rma, 0, op->put.resolved_raddr,
                                 op, 0));
    break;
  case UCT_BXI_IFACE_SEND_OP_TYPE_GET_BCOPY:
    status = uct_bxi_wrap(PtlGet(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                                 op->length, ep->dev_addr.pid,
                                 ep->iface_addr.rma, 0, op->get.resolved_raddr,
                                 op));
    break;
  case UCT_BXI_IFACE_SEND_OP_TYPE_GET_ZCOPY:
    status = uct_bxi_wrap(PtlGet(iface->tx.mem_desc->mdh,
                                 (ptl_size_t)op->get.buffer, op->length,
                                 ep->dev_addr.pid, ep->iface_addr.rma, 0,
                                 op->get.resolved_raddr, op));
    break;
  case UCT_BXI_IFACE_SEND_OP_TYPE_ATOMIC:
    status = uct_bxi_wrap(PtlAtomic(
            iface->tx.mem_desc->mdh, (uint64_t)&op->atomic.value, op->length,
            PTL_ACK_REQ, ep->dev_addr.pid, ep->iface_addr.rma, 0,
            op->atomic.remote_addr, op, 0, op->atomic.op_code, op->atomic.dt));
    break;
  case UCT_BXI_IFACE_SEND_OP_TYPE_FETCH:
    status = uct_bxi_wrap(PtlFetchAtomic(
            iface->tx.mem_desc->mdh, (uint64_t)op->atomic.result,
            iface->tx.mem_desc->mdh, (uint64_t)&op->atomic.value, op->length,
            ep->dev_addr.pid, ep->iface_addr.rma, 0, op->atomic.remote_addr, op,
            0, op->atomic.op_code, op->atomic.dt));
    break;
  case UCT_BXI_IFACE_SEND_OP_TYPE_CAS:
    status = uct_bxi_wrap(PtlSwap(
            iface->tx.mem_desc->mdh, (uint64_t)op->atomic.result,
            iface->tx.mem_desc->mdh, (uint64_t)&op->atomic.value, op->length,
            ep->dev_addr.pid, ep->iface_addr.rma, 0, op->atomic.remote_addr, op,
            0, &op->atomic.compare, PTL_CSWAP, op->atomic.dt));
    break;
  default:
    ucs_error("BXI: unsupported operation. flags=%lx",
              op->flags & UCT_BXI_IFACE_SEND_OP_MASK);
    status = UCS_ERR_UNREACHABLE;
    break;
  }

out:
  return status;
}

// Send calls
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

  UCT_CHECK_AM_ID(id);
  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep, pack,
                                  arg, uct_bxi_send_op_handler, &op->length);
  if (op->length < 0) {
    goto err;
  }

  /* Initialize other operation field. */
  op->am.am_id  = id;
  op->flags    |= UCT_BXI_IFACE_SEND_OP_TYPE_AM;
  op->ep_fb     = ep->fence_beat;
  UCT_BXI_AM_HDR_SET(op->am.hdr, id, ep->conn);
  ep->conn->sn++;

  status = uct_bxi_ep_execute_op(iface, ep, op);
  if (status == UCS_ERR_NO_RESOURCE) {
    op->length = UCS_ERR_NO_RESOURCE;
    goto err_release_op;
  } else if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, AM, BCOPY, op->length);
  uct_bxi_iface_trace_am(ucs_derived_of(tl_ep->iface, uct_bxi_iface_t),
                         UCT_AM_TRACE_TYPE_SEND, id, op + 1, op->length);

  return op->length;
err_release_op:
  ucs_mpool_put(op);
err:
  return op->length;
}

static UCS_F_ALWAYS_INLINE void *uct_bxi_resolve_laddr(void *local_addr,
                                                       uct_bxi_mem_t *mem)
{
  if (mem == (void *)0xdeadbeef) {
    /* Local memory is host memory, no need to resolve it. */
    return local_addr;
  } else {
    return UCS_PTR_BYTE_OFFSET(mem->bar_ptr,
                               (uint64_t)local_addr - mem->info.va);
  }
}

static UCS_F_ALWAYS_INLINE uint64_t uct_bxi_resolve_raddr(uint64_t remote_addr,
                                                          uct_bxi_rkey_t *rkey)
{
  if (rkey->bar_ptr == (void *)0xdeadbeef) {
    /* Remote memory is host memory, no need to resolve it. */
    return remote_addr;
  } else {
    return (uint64_t)UCS_PTR_BYTE_OFFSET(rkey->bar_ptr,
                                         remote_addr - rkey->vaddr);
  }
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
                                  uct_rkey_t uct_rkey)
{
  ucs_status_t             status;
  uct_bxi_iface_send_op_t *op;
  uct_bxi_ep_t            *ep = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface      = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_rkey_t  *rkey       = (uct_bxi_rkey_t *)uct_rkey;

  UCT_CHECK_LENGTH(length, 0, iface->config.max_inline, "put_short");
  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, NULL,
                               uct_bxi_send_op_handler, length);

  /* Compute remote address based on remote gdrcopy registration. */
  op->ep_fb               = ep->fence_beat;
  op->length              = length;
  op->put.buffer          = (void *)buffer; //FIXME: resolve laddr?
  op->flags              |= UCT_BXI_IFACE_SEND_OP_TYPE_PUT_ZCOPY;
  op->put.resolved_raddr  = uct_bxi_resolve_raddr(remote_addr, rkey);

  status = uct_bxi_ep_execute_op(iface, ep, op);
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
                             void *arg, uint64_t remote_addr,
                             uct_rkey_t uct_rkey)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;
  ssize_t                  size = 0;
  uct_bxi_rkey_t          *rkey = (uct_bxi_rkey_t *)uct_rkey;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                  pack_cb, arg, uct_bxi_send_op_handler,
                                  &op->length);
  if (op->length < 0) {
    goto err;
  }
  UCT_SKIP_ZERO_LENGTH(op->length, op);

  /* Compute remote address based on remote gdrcopy registration. */
  op->ep_fb               = ep->fence_beat;
  op->flags              |= UCT_BXI_IFACE_SEND_OP_TYPE_PUT_BCOPY;
  op->put.resolved_raddr  = uct_bxi_resolve_raddr(remote_addr, rkey);

  status = uct_bxi_ep_execute_op(iface, ep, op);
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, PUT, BCOPY, size);
  uct_bxi_log_put(iface);

err:
  return op->length;
}

ucs_status_t uct_bxi_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                  size_t iovcnt, uint64_t remote_addr,
                                  uct_rkey_t uct_rkey, uct_completion_t *comp)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;
  uct_bxi_rkey_t          *rkey = (uct_bxi_rkey_t *)uct_rkey;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_ep_put_zcopy");
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_op_handler, iov->length);

  /* Compute remote address based on remote gdrcopy registration. */
  op->ep_fb               = ep->fence_beat;
  op->length              = iov->length;
  op->put.buffer          = uct_bxi_resolve_laddr(iov->buffer, iov->memh);
  op->flags              |= UCT_BXI_IFACE_SEND_OP_TYPE_PUT_ZCOPY;
  op->put.resolved_raddr  = uct_bxi_resolve_raddr(remote_addr, rkey);

  status = uct_bxi_ep_execute_op(iface, ep, op);
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlPut bcopy return %d", status);
  } else {
    /* For zcopy call, operation is always in progress. */
    status = UCS_INPROGRESS;
  }

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);
  UCT_TL_EP_STAT_OP(&ep->super, PUT, ZCOPY, iov->length);
  uct_bxi_log_put(iface);

err:
  return status;
}

ucs_status_t uct_bxi_ep_get_bcopy(uct_ep_h              tl_ep,
                                  uct_unpack_callback_t unpack_cb, void *arg,
                                  size_t length, uint64_t remote_addr,
                                  uct_rkey_t uct_rkey, uct_completion_t *comp)
{
  ucs_status_t             status;
  uct_bxi_iface_send_op_t *op;
  uct_bxi_ep_t            *ep = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface      = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_rkey_t  *rkey       = (uct_bxi_rkey_t *)uct_rkey;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_GET_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                      unpack_cb, uct_bxi_ep_get_bcopy_handler,
                                      comp, arg, length);

  /* Compute remote address based on remote gdrcopy registration. */
  op->ep_fb               = ep->fence_beat;
  op->length              = length;
  op->flags              |= UCT_BXI_IFACE_SEND_OP_TYPE_GET_BCOPY;
  op->get.resolved_raddr  = uct_bxi_resolve_raddr(remote_addr, rkey);

  status = uct_bxi_ep_execute_op(iface, ep, op);
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
                                  uct_rkey_t uct_rkey, uct_completion_t *comp)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;
  uct_bxi_rkey_t          *rkey = (uct_bxi_rkey_t *)uct_rkey;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_ep_get_zcopy");
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback. */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_op_handler, iov->length);

  /* Compute remote address based on remote gdrcopy registration. */
  op->ep_fb               = ep->fence_beat;
  op->flags              |= UCT_BXI_IFACE_SEND_OP_TYPE_GET_ZCOPY;
  op->put.buffer          = uct_bxi_resolve_laddr(iov->buffer, iov->memh);
  op->length              = iov->length;
  op->get.resolved_raddr  = uct_bxi_resolve_raddr(remote_addr, rkey);

  status = uct_bxi_ep_execute_op(iface, ep, op);
  if (status != UCS_OK) {
    ucs_fatal("BXI: PtlGet bcopy return %d", status);
  } else {
    status = UCS_INPROGRESS;
  }
  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);

  UCT_TL_EP_STAT_OP(&ep->super, GET, ZCOPY, iov->length);
  uct_bxi_log_put(iface);

err:
  return status;
}

static ucs_status_t
uct_bxi_ep_atomic_post_common(uct_ep_h tl_ep, unsigned opcode, uint64_t value,
                              size_t size, ptl_datatype_t dt,
                              uint64_t remote_addr, uct_rkey_t uct_rkey)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_rkey_t  *rkey  = (uct_bxi_rkey_t *)uct_rkey;
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, NULL,
                               uct_bxi_send_ato_op_handler, size);

  /* Store the value since the Atomic call needs an address. */
  op->ep_fb              = ep->fence_beat;
  op->flags              = UCT_BXI_IFACE_SEND_OP_TYPE_ATOMIC;
  op->length             = size;
  op->atomic.dt          = dt;
  op->atomic.op_code     = uct_bxi_atomic_op_table[opcode];
  op->atomic.value       = value;
  op->atomic.remote_addr = uct_bxi_resolve_raddr(remote_addr, rkey);

  status = uct_bxi_ep_execute_op(iface, ep, op);
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
                               uint64_t remote_addr, uct_rkey_t uct_rkey,
                               uct_completion_t *comp)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_rkey_t  *rkey  = (uct_bxi_rkey_t *)uct_rkey;
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_ato_op_handler, size);

  /* Store the value since the Atomic call needs an address. */
  op->ep_fb              = ep->fence_beat;
  op->flags              = UCT_BXI_IFACE_SEND_OP_TYPE_FETCH;
  op->length             = size;
  op->atomic.dt          = dt;
  op->atomic.op_code     = uct_bxi_atomic_op_table[opcode];
  op->atomic.value       = value;
  op->atomic.remote_addr = uct_bxi_resolve_raddr(remote_addr, rkey);
  op->atomic.result      = result;

  status = uct_bxi_ep_execute_op(iface, ep, op);
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
                               uint64_t remote_addr, uct_rkey_t uct_rkey,
                               uint64_t *result, uct_completion_t *comp)
{
  ucs_status_t     status;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_rkey_t  *rkey  = (uct_bxi_rkey_t *)uct_rkey;
  uct_bxi_iface_send_op_t *op;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_ato_op_handler, size);

  /* Store the value since the Atomic call needs an address. */
  op->ep_fb              = ep->fence_beat;
  op->flags              = UCT_BXI_IFACE_SEND_OP_TYPE_CAS;
  op->length             = size;
  op->atomic.dt          = dt;
  op->atomic.remote_addr = uct_bxi_resolve_raddr(remote_addr, rkey);
  op->atomic.result      = result;
  op->atomic.value       = swap;
  op->atomic.compare     = compare;

  status = uct_bxi_ep_execute_op(iface, ep, op);
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
    op->ep           = ep;
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
  uct_bxi_iface_send_op_t *op = NULL;
  uct_bxi_ep_t            *ep = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface      = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);

  //NOTE: Endpoint cannot be fenced if there are no resources since there
  //      may be requests in the pending list. They must be processed before
  //      this fence request.
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  if (ucs_list_is_empty(&ep->send_ops)) {
    UCT_TL_EP_STAT_FENCE(&ep->super);
    return UCS_OK;
  }

  op = ucs_mpool_get(&iface->tx.flush_ops_mp);
  if (op == NULL) {
    return UCS_ERR_NO_MEMORY;
  }
  op->ep           = ep;
  op->user_comp    = NULL;
  op->comp.comp    = 1;
  op->comp.handler = uct_bxi_ep_flush_comp_op_handler;
  op->flags        = UCT_BXI_IFACE_SEND_OP_FLAG_FENCE;

  ep->fence_beat++;

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_flush_op(ep, op);

  UCT_TL_EP_STAT_FENCE(ucs_derived_of(tl_ep, uct_base_ep_t));
  return UCS_OK;
}

//TODO: remove because not used, CONNECT_TO_EP not supported.
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
                               uct_bxi_send_op_handler, 1);

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

//TODO: use arbiter group on each endpoint to enforce fairness between endpoints.
ucs_status_t uct_bxi_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *req,
                                    unsigned flags)
{
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
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
  uct_pending_req_queue_push(&ep->pending_q, req);
  UCT_TL_EP_STAT_PEND(&ep->super);
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
  uct_bxi_ep_t *ep = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_pending_req_priv_queue_t UCS_V_UNUSED *priv;
  uct_bxi_pending_purge_arg_t                purge_arg;

  purge_arg.cb  = cb;
  purge_arg.arg = arg;

  uct_pending_queue_purge(priv, &ep->pending_q, 1, uct_bxi_ep_pending_purge_cb,
                          &purge_arg);
}

UCS_CLASS_INIT_FUNC(uct_bxi_ep_t, const uct_ep_params_t *params)
{
  ucs_status_t      status = UCS_OK;
  uct_bxi_iface_t  *iface  = ucs_derived_of(params->iface, uct_bxi_iface_t);
  uct_bxi_conn_id_t id     = {0};

  UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super);

  if (iface->num_eps + 1 > iface->config.max_num_eps) {
    status = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  self->dev_addr   = *(uct_bxi_device_addr_t *)params->dev_addr;
  self->iface_addr = *(uct_bxi_iface_addr_t *)params->iface_addr;
  self->conn_state = UCT_BXI_EP_CONN_CONNECTED;
  self->flags      = 0;
  self->fence_beat = 0;

  ucs_list_head_init(&self->send_ops);
  ucs_queue_head_init(&self->pending_q);

  id.pid = self->dev_addr.pid;
  id.pti = iface->tm.enabled ? self->iface_addr.ctrl : self->iface_addr.rma;
  id.conn_key = params->field_mask & UCT_EP_PARAM_FIELD_CONN_KEY ?
                        params->conn_key & UCT_BXI_CONN_KEY_MASK :
                        UCT_EP_CONN_KEY_NULL & UCT_BXI_CONN_KEY_MASK;

  /* Get endpoint connection based on triplet. */
  status = uct_bxi_conn_create(iface, id, &self->conn);
  if (status != UCS_OK) {
    goto err;
  }

  /* Append endpoint to interface list. */
  ucs_list_add_head(&iface->eps, &self->elem);

  iface->num_eps++;

err:
  return status;
}

static UCS_CLASS_CLEANUP_FUNC(uct_bxi_ep_t)
{
  uct_bxi_iface_t *iface =
          ucs_derived_of(self->super.super.iface, uct_bxi_iface_t);

  //FIXME: this is blocking. Maybe think of a more clever way to clean
  //       resources
  do {
    uct_bxi_iface_progress(&iface->super.super);
  } while (uct_bxi_iface_flush(&iface->super.super, 0, NULL) != UCS_OK);

  /* Purge all request from the pending queue. */
  uct_bxi_ep_pending_purge(&self->super.super,
                           ucs_empty_function_do_assert_void, NULL);

  ucs_list_del(&self->elem);
  iface->num_eps--;

  return;
}

UCS_CLASS_DEFINE(uct_bxi_ep_t, uct_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_bxi_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_bxi_ep_t, uct_ep_t);
