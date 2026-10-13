#include "bxi_ep.h"
#include <ucs/time/time.h>

#ifdef HAVE_BXIDP
#include <ptlbxi.h>
#endif

#define UCT_BXI_EP_DP_PIO_OFFSET 56

#define UCT_BXI_EP_DP_SET_CMD_SHORT(_slot, _ep, _length, _buffer, _hdr, _tag)  \
  _slot[0] = (uint64_t)(_ep)->inl.s0 | (uint64_t)(_length & 0xffff)            \
                                               << BXI_TX0_LENLO;               \
  _slot[1] = (uint64_t)(_ep)->inl.s1 | (uint64_t)1 << BXI_TX1_PIO |            \
             (uint64_t)(_length >> 16) << BXI_TX1_LENHI;                       \
  _slot[2] = (uint64_t)(_ep)->inl.s2 | (uint64_t)(_buffer) << BXI_TX2_LOFFS;   \
  _slot[3] = (uint64_t)(_ep)->inl.s3;                                          \
  _slot[4] = (uint64_t)(_ep)->inl.s4;                                          \
  _slot[5] = (uint64_t)_hdr << BXI_TX5_HDRDATA;                                \
  _slot[6] = (uint64_t)_tag << BXI_TX6_MATCHBITS;                              \
  _slot[7] = 0;

#define UCT_BXI_EP_DP_SET_CMD_BCOPY(_slot, _ep, _length, _buffer, _hdr, _tag)  \
  _slot[0] = (uint64_t)(_ep)->inl.s0 | (uint64_t)(_length & 0xffff)            \
                                               << BXI_TX0_LENLO;               \
  _slot[1] = (uint64_t)(_ep)->inl.s1 | (uint64_t)1 << BXI_TX1_PIO |            \
             (uint64_t)(_length >> 16) << BXI_TX1_LENHI;                       \
  _slot[2] = (uint64_t)(_ep)->inl.s2 | (uint64_t)(_buffer) << BXI_TX2_LOFFS;   \
  _slot[3] = (uint64_t)(_ep)->inl.s3;                                          \
  _slot[4] = (uint64_t)(_ep)->inl.s4;                                          \
  _slot[5] = (uint64_t)_hdr << BXI_TX5_HDRDATA;                                \
  _slot[6] = (uint64_t)_tag << BXI_TX6_MATCHBITS;                              \
  _slot[7] = 0;

void uct_bxi_ep_dp_cache_slot(uct_bxi_iface_t *iface, uct_bxi_ep_t *ep)
{
  unsigned int          ptl_id;
  struct ptlbxi_ni     *ni     = (struct ptlbxi_ni *)iface->dp.ni;
  struct ptlbxi_mddesc *mddesc = iface->tx.short_mdh.handle;

  ptl_id = BXI_MAKEID(ep->dev_addr.pid.phys.nid, ep->dev_addr.pid.phys.pid);

  ep->inl.s0 = (uint64_t)ptl_id << BXI_TX0_DEST |
               (uint64_t)ni->vni << BXI_TX0_NI |
               (uint64_t)BXI_CMD_PUT << BXI_TX0_CMD |
               (uint64_t)1 << BXI_TX0_CNEW | (uint64_t)1 << BXI_TX0_CEND;
  ep->inl.s1 = (uint64_t)PTL_ACK_REQ << BXI_TX1_ACK | (uint64_t)mddesc->index
                                                              << BXI_TX1_MD;
  ep->inl.s2 = (uint64_t)ep->iface_addr.am << BXI_TX2_PTE;
  ep->inl.s3 = (uint64_t)&iface->dp.dummy;
  ep->inl.s4 = (uint64_t)0 << BXI_TX4_ROFFS | (uint64_t)ni->dev->pid
                                                      << BXI_TX4_PID;
}

UCS_F_MAYBE_UNUSED volatile uint8_t *
uct_bxi_iface_hw_head(uct_bxi_iface_t *iface)
{
  struct ptlbxi_ni *ni = (struct ptlbxi_ni *)iface->dp.ni;
  return ni->dev->txq.hw_head;
}

UCS_F_MAYBE_UNUSED volatile unsigned int *
uct_bxi_iface_tail(uct_bxi_iface_t *iface)
{
  struct ptlbxi_ni *ni = (struct ptlbxi_ni *)iface->dp.ni;
  return ni->dev->txq.tail;
}

ucs_status_t uct_bxi_get_txslot(uct_bxi_iface_t    *iface,
                                volatile uint64_t **slot)
{
  struct ptlbxi_ni *ni = (struct ptlbxi_ni *)iface->dp.ni;
  struct ptlbxi_cq *q  = &ni->dev->txq;
  int               used;

  used = (*q->tail - *q->head) & BXI_TX_PTRMASK;
  if (used >= BXI_CQ_LEN) {
    return UCS_ERR_NO_RESOURCE;
  }

  *slot = (uint64_t *)(q->base + (*q->tail & BXI_CQ_MASK) * BXI_TX_SLOTSIZE);
  return UCS_OK;
}

static void UCS_F_ALWAYS_INLINE uct_bxi_ep_dp_pio_copy(
        volatile void *restrict dst, const void *restrict src, unsigned len)
{
  unsigned           n;
  volatile uint64_t *d = dst;
  const uint64_t    *s = src;

  for (n = 0; n < len; ++n) {
    *d++ = *s++;
  }
}

void uct_bxi_ep_dp_write(uct_bxi_iface_t *iface, uct_bxi_ep_t *ep,
                         volatile uint64_t *slot, uint8_t am_id, uint64_t hdr,
                         const void *buffer, unsigned length)
{
  ptl_hdr_data_t ptl_hdr;
  unsigned       num_write;

  /* Start by copying PIO payload. Round up to generate only uint64_t write. */
  num_write = ucs_div_round_up(length, sizeof(uint64_t));
  uct_bxi_ep_dp_pio_copy((volatile char *)slot + UCT_BXI_EP_DP_PIO_OFFSET,
                         buffer, num_write);

  /* Payload and command must be fenced. */
  ucs_memory_bus_store_fence();

  /* Set header data and increment connection sequence number. */
  UCT_BXI_AM_HDR_SET(ptl_hdr, UCT_BXI_AM_HANDLER_SHORT, sizeof(uint64_t), am_id,
                     ep->conn);
  ep->conn->sn++;

  /* Write command to NIC BAR slot. */
  UCT_BXI_EP_DP_SET_CMD_SHORT(slot, ep, length, buffer, ptl_hdr, hdr);
}

void uct_bxi_txslot_commit(uct_bxi_iface_t *iface)
{
  struct ptlbxi_ni *ni = (struct ptlbxi_ni *)iface->dp.ni;
  struct ptlbxi_cq *q  = &ni->dev->txq;

  (*q->tail)++;

  /*
	 * ensure the command is not write combined
	 * with future commands and/or payload
	 */
  ucs_memory_bus_store_fence();
}

ucs_status_t uct_bxi_ep_dp_am_short(uct_ep_h tl_ep, uint8_t am_id, uint64_t hdr,
                                    const void *buffer, unsigned length)
{
  ucs_status_t       status = UCS_OK;
  uct_bxi_ep_t      *ep     = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t   *iface  = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  struct ptlbxi_ni  *ni     = (struct ptlbxi_ni *)iface->dp.ni;
  struct ptlbxi_cq  *q      = &ni->dev->txq;
  ptl_hdr_data_t     ptl_hdr;
  unsigned           num_write;
  volatile uint64_t *slot;

  UCT_CHECK_AM_ID(am_id);
  UCT_BXI_CHECK_EP(ep);

  pthread_mutex_lock(&ni->dev->tx_lock.mutex);

  /* Try to get a slot from the tx queue. */
  status = uct_bxi_get_txslot(iface, &slot);
  if (status == UCS_ERR_NO_RESOURCE) {
    goto err;
  }

  /* Start by copying PIO payload. Round up to generate only uint64_t write. */
  num_write = ucs_div_round_up(length, sizeof(uint64_t));
  uct_bxi_ep_dp_pio_copy((volatile char *)slot + UCT_BXI_EP_DP_PIO_OFFSET,
                         buffer, num_write);

  /* Payload and command must be fenced. */
  ucs_memory_bus_store_fence();

  /* Set header data and increment connection sequence number. */
  UCT_BXI_AM_HDR_SET(ptl_hdr, UCT_BXI_AM_HANDLER_SHORT, sizeof(uint64_t), am_id,
                     ep->conn);
  ep->conn->sn++;

  /* Write command to NIC BAR slot. */
  UCT_BXI_EP_DP_SET_CMD_SHORT(slot, ep, length, buffer, ptl_hdr, hdr);

  /* Commit slot and ensure it is fenced with the next command. */
  (*q->tail)++;
  ucs_memory_bus_store_fence();

  uct_bxi_ep_enable_flush(ep);
  uct_bxi_conn_enable(ep->conn);

err:
  pthread_mutex_unlock(&ni->dev->tx_lock.mutex);
  return status;
}

ssize_t uct_bxi_ep_dp_am_bcopy(uct_ep_h tl_ep, uint8_t id,
                               uct_pack_callback_t pack, void *arg,
                               unsigned flags)
{
  ucs_status_t       status = UCS_OK;
  uct_bxi_ep_t      *ep     = ucs_derived_of(tl_ep, uct_bxi_ep_t);
  uct_bxi_iface_t   *iface  = ucs_derived_of(tl_ep->iface, uct_bxi_iface_t);
  struct ptlbxi_ni  *ni     = (struct ptlbxi_ni *)iface->dp.ni;
  volatile uint64_t *slot;
  uct_bxi_iface_send_op_t *op;
  ptl_hdr_data_t           ptl_hdr;

  UCT_CHECK_AM_ID(id);
  UCT_BXI_CHECK_EP(ep);
  UCT_BXI_CHECK_IFACE_RES(iface, ep);

  pthread_mutex_lock(&ni->dev->tx_lock.mutex);

  /* Try to get a slot from the tx queue. */
  status = uct_bxi_get_txslot(iface, &slot);
  if (status == UCS_ERR_NO_RESOURCE) {
    pthread_mutex_unlock(&ni->dev->tx_lock.mutex);
    return status;
  }

  /* Take a bcopy send descriptor from the memory pool. Descriptor has 
   * an operation first, then a buffer of size seg_size. */
  UCT_BXI_IFACE_GET_TX_BCOPY_DESC(iface, &iface->tx.send_desc_mp, op, ep, pack,
                                  arg, uct_bxi_send_op_handler, &op->length);
  if (op->length < 0) {
    goto err;
  }

  /* Set header data and increment connection sequence number. */
  UCT_BXI_AM_HDR_SET(ptl_hdr, UCT_BXI_AM_HANDLER_BCOPY, 0, id, ep->conn);
  ep->conn->sn++;

  /* Write command to NIC BAR slot. */
  UCT_BXI_EP_DP_SET_CMD_BCOPY(slot, ep, op->length, op + 1, ptl_hdr, 0);

  uct_bxi_txslot_commit(iface);

  pthread_mutex_unlock(&ni->dev->tx_lock.mutex);

  /* Append operation descriptor to completion queue. */
  uct_bxi_ep_add_send_op(ep, op);
  uct_bxi_ep_enable_flush(ep);
  uct_bxi_conn_enable(ep->conn);

  UCT_TL_EP_STAT_OP(&ep->super, AM, BCOPY, op->length);
  uct_bxi_iface_trace_am(ucs_derived_of(tl_ep->iface, uct_bxi_iface_t),
                         UCT_AM_TRACE_TYPE_SEND, id, op + 1, op->length);

  return op->length;
err_release_op:
  ep->conn->sn--;
  ucs_mpool_put(op);
err:
  return op->length;
}
