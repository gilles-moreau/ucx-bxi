#include "ptl_am_ep.h"
#include "ptl_am_iface.h"
#include "ptl_types.h"

#include <uct/base/uct_log.h>

ucs_status_t uct_ptl_am_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t hdr,
                                    const void *buffer, unsigned length) {
  ucs_status_t rc;
  ptl_match_bits_t am_hdr = 0;
  uct_ptl_am_ep_t *ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_ptl_am_iface_t);

  return UCS_ERR_UNSUPPORTED;

  ucs_assert(length <= iface->super.config.max_short);

  UCT_PTL_HDR_SET(am_hdr, id, UCT_PTL_AM_SHORT);
  ep->am_mmd->seqn++;

  rc = uct_ptl_wrap(PtlPut(ep->am_mmd->mdh, (ptl_size_t)buffer, length,
                           PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.am_pti, am_hdr, 0, NULL, hdr));

  return rc;
}

ucs_status_t uct_ptl_am_ep_am_short_iov(uct_ep_h tl_ep, uint8_t id,
                                        const uct_iov_t *iov, size_t iovcnt) {
  ucs_status_t rc;
  ptl_match_bits_t am_hdr = 0;
  uct_ptl_am_ep_t *ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_ptl_am_iface_t);

  return UCS_ERR_UNSUPPORTED;

  ucs_assert(iovcnt == 1 && iov->length <= iface->super.config.max_short);

  UCT_PTL_HDR_SET(am_hdr, id, UCT_PTL_AM_BCOPY);
  ep->am_mmd->seqn++;

  rc = uct_ptl_wrap(PtlPut(ep->am_mmd->mdh, (ptl_size_t)iov->buffer,
                           iov->length, PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.am_pti, am_hdr, 0, NULL, 0));

  return rc;
}

ssize_t uct_ptl_am_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id,
                               uct_pack_callback_t pack, void *arg,
                               unsigned flags) {
  ucs_status_t rc = UCS_OK;
  ptl_match_bits_t hdr = 0;
  uct_ptl_am_ep_t *ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_op_t *op;
  void *start = NULL;
  ssize_t size = 0;

  UCT_CHECK_AM_ID(id);

  op = ucs_mpool_get(ep->bcopy_mp);
  if (op == NULL) {
    size = UCS_ERR_NO_RESOURCE;
    goto err;
  }
  op->comp = NULL;
  op->seqn = ep->am_mmd->seqn++;

  start = (void *)(op + 1);
  ucs_assert(start != NULL);

  size = pack(start, arg);
  if (size < 0) {
    goto err;
  }

  UCT_PTL_HDR_SET(hdr, id, UCT_PTL_AM_BCOPY);
  rc = uct_ptl_wrap(PtlPut(ep->am_mmd->mdh, (ptl_size_t)start, size,
                           PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.am_pti, hdr, 0, NULL, 0));

  if (rc != UCS_OK) {
    ucs_mpool_put(op);
    ep->am_mmd->seqn++;
    size = UCS_ERR_IO_ERROR;
    goto err;
  }

  ucs_queue_push(&ep->am_mmd->opq, &op->elem);

  uct_ptl_iface_trace_am(ucs_derived_of(tl_ep->iface, uct_ptl_am_iface_t),
                         UCT_AM_TRACE_TYPE_SEND, id, start, size);
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
  ucs_status_t rc;
  uct_ptl_am_ep_t *ptl_ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_op_t *op = ucs_mpool_get(ptl_ep->zcopy_mp);

  if (op == NULL) {
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op->comp = NULL;
  op->seqn = ptl_ep->rma_mmd->seqn++;

  if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_DATA)) {
    char buf[256] = {0};
    uct_log_data(__FILE__, __LINE__, __func__, buf);
  }

  rc =
      uct_ptl_wrap(PtlPut(ptl_ep->rma_mmd->mdh, (ptl_size_t)buffer, length,
                          PTL_CT_ACK_REQ, ptl_ep->super.dev_addr.pid,
                          ptl_ep->iface_addr.rma_pti, 0, remote_addr, NULL, 0));

  if (rc != UCS_OK) {
    ucs_mpool_put(op);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  ucs_queue_push(&ptl_ep->rma_mmd->opq, &op->elem);

err:
  return rc;
}

ssize_t uct_ptl_am_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                                void *arg, uint64_t remote_addr,
                                uct_rkey_t rkey) {
  ucs_status_t rc = UCS_OK; // FIXME: remove rc?
  uct_ptl_am_ep_t *ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_op_t *op;
  void *start = NULL;
  ssize_t size = 0;

  op = ucs_mpool_get(ep->bcopy_mp);

  if (op == NULL) {
    size = UCS_ERR_NO_RESOURCE;
    goto err;
  }
  op->comp = NULL;
  op->seqn = ep->rma_mmd->seqn++;

  start = (void *)(op + 1);
  if (start == NULL) {
    ucs_error("PTL: could not allocate bcopy buffer.");
    size = UCS_ERR_NO_RESOURCE;
    goto err;
  }
  size = pack_cb(start, arg);
  if (size < 0) {
    goto err;
  }

  if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_DATA)) {
    char buf[256] = {0};
    uct_log_data(__FILE__, __LINE__, __func__, buf);
  }

  rc = uct_ptl_wrap(PtlPut(ep->rma_mmd->mdh, (ptl_size_t)start, size,
                           PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                           ep->iface_addr.rma_pti, 0, remote_addr, NULL, 0));

  if (rc != UCS_OK) {
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
                                     uct_rkey_t rkey, uct_completion_t *comp) {
  ucs_status_t rc;
  uct_ptl_am_ep_t *ptl_ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_op_t *op = ucs_mpool_get(ptl_ep->zcopy_mp);

  ucs_assert(iovcnt == 1);

  if (op == NULL) {
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op->comp = comp;
  op->size = iov[0].length;
  op->seqn = ptl_ep->rma_mmd->seqn++;

  if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_DATA)) {
    char buf[256] = {0};
    uct_log_data(__FILE__, __LINE__, __func__, buf);
  }

  rc =
      uct_ptl_wrap(PtlPut(ptl_ep->rma_mmd->mdh, (ptl_size_t)iov[0].buffer,
                          op->size, PTL_CT_ACK_REQ, ptl_ep->super.dev_addr.pid,
                          ptl_ep->iface_addr.rma_pti, 0, remote_addr, NULL, 0));

  if (rc != UCS_OK) {
    ucs_mpool_put(op);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  rc = UCS_INPROGRESS;
  ucs_queue_push(&ptl_ep->rma_mmd->opq, &op->elem);

err:
  return rc;
}

ucs_status_t uct_ptl_am_ep_get_bcopy(uct_ep_h tl_ep,
                                     uct_unpack_callback_t unpack_cb, void *arg,
                                     size_t length, uint64_t remote_addr,
                                     uct_rkey_t rkey, uct_completion_t *comp) {
  ucs_status_t rc = UCS_OK; // FIXME: remove rc?
  uct_ptl_am_ep_t *ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_op_t *op;
  void *start = NULL;

  op = ucs_mpool_get(ep->bcopy_mp);
  if (op == NULL) {
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }
  op->type = UCT_PTL_OP_RMA_GET_BCOPY;
  op->comp = comp;
  op->seqn = ep->rma_mmd->seqn++;
  op->size = length;
  op->get_bcopy.unpack = unpack_cb;
  op->get_bcopy.arg = arg;

  start = (void *)(op + 1);
  ucs_assert(start != NULL);

  if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_DATA)) {
    char buf[256] = {0};
    uct_log_data(__FILE__, __LINE__, __func__, buf);
  }

  rc = uct_ptl_wrap(PtlGet(ep->rma_mmd->mdh, (uint64_t)start, length,
                           ep->super.dev_addr.pid, ep->iface_addr.rma_pti, 0,
                           remote_addr, NULL));

  if (rc != UCS_OK) {
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
                                     uct_rkey_t rkey, uct_completion_t *comp) {
  ucs_status_t rc;
  uct_ptl_am_ep_t *ptl_ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_op_t *op = ucs_mpool_get(ptl_ep->zcopy_mp);

  if (op == NULL) {
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op->comp = comp;
  op->size = iov[0].length;
  op->seqn = ptl_ep->rma_mmd->seqn++;

  if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_DATA)) {
    char buf[256] = {0};
    uct_log_data(__FILE__, __LINE__, __func__, buf);
  }

  rc = uct_ptl_wrap(PtlGet(ptl_ep->rma_mmd->mdh, (ptl_size_t)iov[0].buffer,
                           op->size, ptl_ep->super.dev_addr.pid,
                           ptl_ep->iface_addr.rma_pti, 0, remote_addr, NULL));

  if (rc != UCS_OK) {
    ucs_mpool_put(op);
    rc = UCS_ERR_IO_ERROR;
    goto err;
  }

  rc = UCS_INPROGRESS;
  ucs_queue_push(&ptl_ep->rma_mmd->opq, &op->elem);

err:
  return rc;
}

static ucs_status_t
uct_ptl_am_ep_atomic_post_common(uct_ep_h tl_ep, unsigned opcode,
                                 uint64_t value, size_t size, ptl_datatype_t dt,
                                 uint64_t remote_addr, uct_rkey_t rkey) {
  ucs_status_t rc;
  uct_ptl_am_ep_t *ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_op_t *op = ucs_mpool_get(ep->zcopy_mp);

  if (op == NULL) {
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op->type = UCT_PTL_OP_ATOMIC_POST;
  op->comp = NULL;
  op->seqn = ep->rma_mmd->seqn++;
  op->ato.value = value;

  rc = uct_ptl_wrap(PtlAtomic(ep->rma_mmd->mdh, (uint64_t)&op->ato.value, size,
                              PTL_CT_ACK_REQ, ep->super.dev_addr.pid,
                              ep->iface_addr.rma_pti, 0, remote_addr, NULL, 0,
                              uct_ptl_atomic_op_table[opcode], dt));

  if (rc != UCS_OK) {
    ucs_mpool_put(op);
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
                                  uct_rkey_t rkey, uct_completion_t *comp) {

  ucs_status_t rc;
  uct_ptl_am_ep_t *ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_op_t *op = ucs_mpool_get(ep->zcopy_mp);

  if (op == NULL) {
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op->comp = comp;
  op->seqn = ep->rma_mmd->seqn++;
  op->ato.value = value;

  ucs_debug("PTL: fetch start. op=%p, seqn=%lu", op, op->seqn);
  rc = uct_ptl_wrap(PtlFetchAtomic(ep->rma_mmd->mdh, (uint64_t)result,
                                   ep->rma_mmd->mdh, (uint64_t)&op->ato.value,
                                   size, ep->super.dev_addr.pid,
                                   ep->iface_addr.rma_pti, 0, remote_addr, NULL,
                                   0, uct_ptl_atomic_op_table[opcode], dt));

  if (rc != UCS_OK) {
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
                                  uint64_t *result, uct_completion_t *comp) {
  ucs_status_t rc;
  uct_ptl_am_ep_t *ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_op_t *op = ucs_mpool_get(ep->zcopy_mp);

  if (op == NULL) {
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }

  op->comp = comp;
  op->seqn = ep->rma_mmd->seqn++;
  op->ato.value = swap;
  op->ato.compare = compare;

  rc = uct_ptl_wrap(PtlSwap(ep->rma_mmd->mdh, (uint64_t)result,
                            ep->rma_mmd->mdh, (uint64_t)&op->ato.value, size,
                            ep->super.dev_addr.pid, ep->iface_addr.rma_pti, 0,
                            remote_addr, NULL, 0, &op->ato.compare, PTL_CSWAP,
                            dt));

  if (rc != UCS_OK) {
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
                                          uct_completion_t *comp) {
  return uct_ptl_am_ep_atomic_cswap_common(
      tl_ep, (uint64_t)compare, (uint64_t)swap, sizeof(uint32_t), PTL_UINT32_T,
      remote_addr, rkey, (uint64_t *)result, comp);
}

ucs_status_t uct_ptl_am_ep_atomic32_post(uct_ep_h tl_ep, unsigned opcode,
                                         uint32_t value, uint64_t remote_addr,
                                         uct_rkey_t rkey) {
  return uct_ptl_am_ep_atomic_post_common(
      tl_ep, opcode, value, sizeof(uint32_t), PTL_UINT32_T, remote_addr, rkey);
}

ucs_status_t uct_ptl_am_ep_atomic32_fetch(uct_ep_h tl_ep, unsigned opcode,
                                          uint32_t value, uint32_t *result,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp) {
  return uct_ptl_am_ep_atomic_fetch_common(
      tl_ep, opcode, (uint64_t)value, (uint64_t *)result, sizeof(uint32_t),
      PTL_UINT32_T, remote_addr, rkey, comp);
}

ucs_status_t uct_ptl_am_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare,
                                          uint64_t swap, uint64_t remote_addr,
                                          uct_rkey_t rkey, uint64_t *result,
                                          uct_completion_t *comp) {
  return uct_ptl_am_ep_atomic_cswap_common(tl_ep, compare, swap,
                                           sizeof(uint64_t), PTL_UINT64_T,
                                           remote_addr, rkey, result, comp);
}

ucs_status_t uct_ptl_am_ep_atomic64_post(uct_ep_h tl_ep, unsigned opcode,
                                         uint64_t value, uint64_t remote_addr,
                                         uct_rkey_t rkey) {

  return uct_ptl_am_ep_atomic_post_common(
      tl_ep, opcode, value, sizeof(uint64_t), PTL_UINT64_T, remote_addr, rkey);
}

ucs_status_t uct_ptl_am_ep_atomic64_fetch(uct_ep_h tl_ep,
                                          uct_atomic_op_t opcode,
                                          uint64_t value, uint64_t *result,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp) {
  return uct_ptl_am_ep_atomic_fetch_common(tl_ep, opcode, value, result,
                                           sizeof(uint64_t), PTL_UINT64_T,
                                           remote_addr, rkey, comp);
}

ucs_status_t uct_ptl_am_ep_flush(uct_ep_h tl_ep, unsigned flags,
                                 uct_completion_t *comp) {
  return uct_ptl_am_iface_flush(tl_ep->iface, flags, comp);
}

ucs_status_t uct_ptl_am_ep_fence(uct_ep_h tl_ep, unsigned flags) {
  return uct_ptl_am_iface_fence(tl_ep->iface, flags);
}

void uct_ptl_am_ep_post_check(uct_ep_h tl_ep) { return; }

ucs_status_t uct_ptl_am_ep_get_address(uct_ep_h tl_ep, uct_ep_addr_t *addr) {
  uct_ptl_am_ep_t *ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_am_ep_addr_t *ptl_addr = (uct_ptl_am_ep_addr_t *)addr;

  ptl_addr->super.dev_addr = ep->super.dev_addr;
  ptl_addr->iface_addr = ep->iface_addr;

  return UCS_OK;
}

int uct_ptl_am_ep_is_connected(const uct_ep_h tl_ep,
                               const uct_ep_is_connected_params_t *params) {
  int is_connected = 1;
  uct_ptl_am_ep_t *ep = ucs_derived_of(tl_ep, uct_ptl_am_ep_t);
  uct_ptl_device_addr_t *dest_device_addr;
  uct_ptl_am_iface_addr_t *dest_iface_addr;

  UCT_EP_IS_CONNECTED_CHECK_DEV_IFACE_ADDRS(params);

  dest_device_addr = (uct_ptl_device_addr_t *)params->device_addr;
  dest_iface_addr = (uct_ptl_am_iface_addr_t *)params->iface_addr;

  if (!uct_ptl_iface_cmp_device_addr(&ep->super.dev_addr, dest_device_addr) ||
      !uct_ptl_am_iface_cmp_iface_addr(&ep->iface_addr, dest_iface_addr)) {
    is_connected = 0;
  }

  return is_connected;
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

  self->bcopy_mp = &iface->bcopy_mp;
  self->zcopy_mp = &iface->zcopy_mp;
  self->am_mmd = &iface->am_mmd;
  self->rma_mmd = iface->rma_mmd;

  self->iface_addr = *addr;

  return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ptl_am_ep_t) {
  ucs_debug("destroy ptl ep %p", self);
  return;
}

UCS_CLASS_DEFINE(uct_ptl_am_ep_t, uct_ptl_ep_t);
UCS_CLASS_DEFINE_NEW_FUNC(uct_ptl_am_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DEFINE_DELETE_FUNC(uct_ptl_am_ep_t, uct_ep_t);
