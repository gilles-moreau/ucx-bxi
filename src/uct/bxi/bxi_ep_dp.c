#include "bxi_ep.h"

void print_vector(volatile uint64_t *vector)
{
  for (size_t i = 0; i < 64; ++i)
    ucs_debug("[%2zu] 0x%016" PRIx64 "\n", i, vector[i]);
}

static ucs_status_t uct_bxi_get_txslot(uct_bxi_iface_t    *iface,
                                       volatile uint64_t **slot,
                                       volatile uint64_t **slot_p)
{
  struct ptlbxi_cq *q = &iface->dp.ni->dev->txq;
  int               used;

  used = (*q->tail - *q->head) & BXI_TX_PTRMASK;
  if (used >= BXI_CQ_LEN) {
    *q->head = *q->hw_head;
    used     = (*q->tail - *q->head) & BXI_TX_PTRMASK;
  }
  if (used >= BXI_CQ_LEN) {
    return UCS_ERR_NO_RESOURCE;
  }

  *slot   = (uint64_t *)(q->base + (*q->tail & BXI_CQ_MASK) * BXI_TX_SLOTSIZE);
  *slot_p = (uint64_t *)(q->base +
                         ((*q->tail - 1) & BXI_CQ_MASK) * BXI_TX_SLOTSIZE);
  ucs_debug("BXIDP: txq. head=%d, hwhead=%d, tail=%d, slot=%p", *q->head,
            *q->hw_head, *q->tail, *slot);
  return UCS_OK;
}

static void uct_bxi_txslot_commit(uct_bxi_iface_t *iface)
{
  struct ptlbxi_cq *q = &iface->dp.ni->dev->txq;

  (*q->tail)++;

  ucs_debug("BXIDP: txq. head=%d, hwhead=%d, tail=%d", *q->head, *q->hw_head,
            *q->tail);

  /*
	 * ensure the command is not write combined
	 * with future commands and/or payload
	 */
  ucs_memory_bus_store_fence();

  ucs_debug("BXIDP: txq. head=%d, hwhead=%d, tail=%d", *q->head, *q->hw_head,
            *q->tail);
}

static void uct_bxi_txslot_set(uct_bxi_iface_t         *iface,
                               uct_bxi_iface_send_op_t *op,
                               volatile uint64_t       *slot_p)
{
  uint64_t              slot[64];
  struct ptlbxi_mddesc *mddesc = iface->tx.mdh.handle;
  volatile char        *pioptr;
  unsigned int          id = BXI_MAKEID(op->ep->dev_addr.pid.phys.nid,
                                        op->ep->dev_addr.pid.phys.pid);

  pioptr = (volatile char *)slot + 64 - 8;

  slot[0] = (uint64_t)id << BXI_TX0_DEST |
            (uint64_t)iface->dp.ni->vni << BXI_TX0_NI |
            (uint64_t)BXI_CMD_PUT << BXI_TX0_CMD | (uint64_t)1 << BXI_TX0_CNEW |
            (uint64_t)1 << BXI_TX0_CEND |
            (uint64_t)(op->length & 0xffff) << BXI_TX0_LENLO;
  slot[1] = (uint64_t)0 | (uint64_t)(op->length >> 16) << BXI_TX1_LENHI |
            (uint64_t)PTL_ACK_REQ << BXI_TX1_ACK |
            (uint64_t)mddesc->index << BXI_TX1_MD;
  slot[2] = (uint64_t)op->ep->iface_addr.am << BXI_TX2_PTE |
            (uint64_t)op->am.buffer << BXI_TX2_LOFFS;
  slot[3] = (uint64_t)op << BXI_TX3_UPTR;
  slot[4] = (uint64_t)0 << BXI_TX4_ROFFS | (uint64_t)iface->dp.ni->dev->pid
                                                   << BXI_TX4_PID;
  slot[5] = (uint64_t)op->am.hdr << BXI_TX5_HDRDATA;
  slot[6] = (uint64_t)0 << BXI_TX6_MATCHBITS;
  *pioptr = 0;

  ucs_memory_bus_store_fence();

  print_vector(slot);

  memcpy((uint64_t *)slot_p, &slot, sizeof(slot));
  print_vector(slot_p);
}

ucs_status_t uct_bxi_ep_dp_am_bcopy(uct_bxi_iface_t *iface, uct_bxi_ep_t *ep,
                                    uct_bxi_iface_send_op_t *op)
{
  ucs_status_t       status;
  volatile uint64_t *slot, *slot_p;

  status = uct_bxi_get_txslot(iface, &slot, &slot_p);
  if (status != UCS_OK) {
    goto err;
  }

  uct_bxi_txslot_set(iface, op, slot);

  ucs_memory_bus_load_fence();

  print_vector(slot);
  print_vector(slot_p);

  uct_bxi_txslot_commit(iface);

err:
  return status;
}
