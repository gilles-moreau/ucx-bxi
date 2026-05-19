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
  //NOTE: flush operation are only used when a user_comp is provided
  if (op->flags & UCT_BXI_IFACE_SEND_OP_FLAG_FLUSH) {
    uct_invoke_completion(op->user_comp, UCS_OK);
  }

  uct_bxi_ep_remove_from_queue(op);
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
  ptl_size_t               size;

  UCT_CHECK_AM_ID(id);
  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep, pack,
                                  arg, uct_bxi_send_op_handler, &size);
  if (size < 0) {
    goto err;
  }

  //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               size, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.am, 0, 0, op, id));

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
  uint64_t         resolved_raddr;

  UCT_CHECK_LENGTH(length, 0, iface->config.max_inline, "put_short");
  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, NULL,
                               uct_bxi_send_op_handler, length);

  /* Compute remote address based on remote gdrcopy registration. */
  resolved_raddr = uct_bxi_resolve_raddr(remote_addr, rkey);

  //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)buffer,
                               length, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.rma, 0, resolved_raddr, op, 0));
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
  uint64_t                 resolved_raddr;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                  pack_cb, arg, uct_bxi_send_op_handler, &size);
  if (size < 0) {
    goto err;
  }
  UCT_SKIP_ZERO_LENGTH(size, op);

  /* Compute remote address based on remote gdrcopy registration. */
  resolved_raddr = uct_bxi_resolve_raddr(remote_addr, rkey);

  //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               size, PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.rma, 0, resolved_raddr, op, 0));
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
                                  uct_rkey_t uct_rkey, uct_completion_t *comp)
{
  ucs_status_t     status;
  ptl_iovec_t     *ptl_iov;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;
  uct_bxi_rkey_t          *rkey = (uct_bxi_rkey_t *)uct_rkey;
  uint64_t                 resolved_raddr;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_ep_put_zcopy");
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_op_handler,
                               uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov = ucs_alloca(iovcnt * sizeof(ptl_iovec_t));
  uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);

  /* Compute remote address based on remote gdrcopy registration. */
  resolved_raddr = uct_bxi_resolve_raddr(remote_addr, rkey);

  //TODO: replace by PtlPutNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlPut(iface->tx.mem_desc->mdh,
                               (ptl_size_t)ptl_iov->iov_base, ptl_iov->iov_len,
                               PTL_ACK_REQ, ep->dev_addr.pid,
                               ep->iface_addr.rma, 0, resolved_raddr, op, 0));
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
                                  uct_rkey_t uct_rkey, uct_completion_t *comp)
{
  ucs_status_t             status;
  uct_bxi_iface_send_op_t *op;
  uct_bxi_ep_t            *ep = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface      = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_rkey_t  *rkey       = (uct_bxi_rkey_t *)uct_rkey;
  uint64_t         resolved_raddr;

  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_GET_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep,
                                      unpack_cb, uct_bxi_ep_get_bcopy_handler,
                                      comp, arg, length);

  /* Compute remote address based on remote gdrcopy registration. */
  resolved_raddr = uct_bxi_resolve_raddr(remote_addr, rkey);

  //TODO: replace by PtlGetNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlGet(iface->tx.mem_desc->mdh, (ptl_size_t)(op + 1),
                               length, ep->dev_addr.pid, ep->iface_addr.rma, 0,
                               resolved_raddr, op));
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
  size_t           iov_size;
  ptl_iovec_t     *ptl_iov;
  uct_bxi_ep_t    *ep    = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  uct_bxi_iface_send_op_t *op;
  uct_bxi_rkey_t          *rkey = (uct_bxi_rkey_t *)uct_rkey;
  uint64_t                 resolved_raddr;

  UCT_BXI_CHECK_EP(ep);
  UCT_CHECK_IOV_SIZE(iovcnt, (unsigned long)iface->config.max_iovecs,
                     "uct_bxi_ep_get_zcopy");
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  /* First, get OP while setting appropriate completion callback */
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_op_handler,
                               uct_iov_total_length(iov, iovcnt));

  //TODO: sometimes, implement support for PTL_IOVEC for MD.
  ptl_iov  = ucs_alloca(iovcnt * sizeof(ptl_size_t));
  iov_size = uct_bxi_fill_ptl_iovec(ptl_iov, iov, iovcnt);
  //FIXME: redundant UCT_SKIP_ZERO_LENGTH?
  UCT_SKIP_ZERO_LENGTH(iov_size);

  /* Compute remote address based on remote gdrcopy registration. */
  resolved_raddr = uct_bxi_resolve_raddr(remote_addr, rkey);

  //TODO: replace by PtlGetNB and handle PTL_TRY_AGAIN
  status = uct_bxi_wrap(PtlGet(iface->tx.mem_desc->mdh,
                               (ptl_size_t)ptl_iov->iov_base, ptl_iov->iov_len,
                               ep->dev_addr.pid, ep->iface_addr.rma, 0,
                               resolved_raddr, op));

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
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, NULL,
                               uct_bxi_send_ato_op_handler, size);

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
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_ato_op_handler, size);

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
  UCT_BXI_IFACE_GET_TX_OP_COMP(iface, &iface->tx.send_op_mp, op, ep, comp,
                               uct_bxi_send_ato_op_handler, size);

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

  ucs_list_for_each (op, &ep->send_ops, elem) {
    ucs_debug("BXI: op=%p, comp=%d, flags=%08x", op, op->comp.comp, op->flags);
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

static UCS_F_ALWAYS_INLINE khint_t
uct_bxi_conn_map_conn_hash(uct_bxi_ep_conn_t *conn)
{
  return ucs_crc32(0, &conn->id, sizeof(conn->id));
}

static UCS_F_ALWAYS_INLINE int
uct_bxi_conn_map_conn_equal(uct_bxi_ep_conn_t *conn1, uct_bxi_ep_conn_t *conn2)
{
  return (conn1->id.pid.phys.nid == conn2->id.pid.phys.nid) &&
         (conn1->id.pid.phys.pid == conn2->id.pid.phys.pid) &&
         (conn1->id.pti == conn2->id.pti) &&
         (conn1->id.conn_key == conn2->id.conn_key);
}

__KHASH_IMPL(uct_bxi_conn_map, kh_inline, uct_bxi_ep_conn_t *, char, 0,
             uct_bxi_conn_map_conn_hash, uct_bxi_conn_map_conn_equal);

ucs_status_t uct_bxi_iface_get_conn(uct_bxi_iface_t    *iface,
                                    uct_bxi_conn_id_t   id,
                                    uct_bxi_ep_conn_t **conn_p)
{
  int                ret;
  khiter_t           iter;
  uct_bxi_ep_conn_t *conn;

  conn = ucs_malloc(sizeof(uct_bxi_ep_conn_t), "bxi ep conn");
  if (conn == NULL) {
    ucs_fatal("BXI: failed to allocate bxi endpoint connection.");
  }

  conn->id = id;
  iter     = kh_put(uct_bxi_conn_map, &iface->conn_map, conn, &ret);
  ucs_assertv((ret != UCS_KH_PUT_FAILED), "ret %d", ret);

  /* Get the connection or create it if it does not exist and add 
   * it to the hash table. */
  if (ret == UCS_KH_PUT_KEY_PRESENT) {
    ucs_free(conn);
    conn = kh_key(&iface->conn_map, iter);
    goto out;
  }

  /* Initialize counters. */
  conn->cnt = conn->send = conn->recv = 0;

out:
  *conn_p = conn;

  return UCS_OK;
}

UCS_CLASS_INIT_FUNC(uct_bxi_ep_t, const uct_ep_params_t *params)
{
  ucs_status_t      status = UCS_OK;
  uct_bxi_iface_t  *iface  = ucs_derived_of(params->iface, uct_bxi_iface_t);
  uct_bxi_conn_id_t id;

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
  ucs_list_head_init(&self->fenced_ops);
  ucs_queue_head_init(&self->pending_q);

  id.pid      = self->dev_addr.pid;
  id.pti      = iface->tm.enabled ? uct_bxi_rxq_get_addr(iface->rx.tag.q) :
                                    UCT_BXI_PT_NULL;
  id.conn_key = params->field_mask & UCT_EP_PARAM_FIELD_CONN_KEY ?
                        params->conn_key :
                        UCT_EP_CONN_KEY_NULL;

  /* Get endpoint connection based on triplet. */
  status = uct_bxi_iface_get_conn(iface, id, &self->conn);
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
  khiter_t         iter;
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

  /* Destroy endpoint connection. */
  iter = kh_get(uct_bxi_conn_map, &iface->conn_map, self->conn);
  kh_del(uct_bxi_conn_map, &iface->conn_map, iter);
  ucs_free(self->conn);

  ucs_list_del(&self->elem);
  iface->num_eps--;

  return;
}

UCS_CLASS_DEFINE(uct_bxi_ep_t, uct_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_bxi_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_bxi_ep_t, uct_ep_t);
