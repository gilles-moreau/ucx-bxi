#include "bxi_ep.h"

static ucs_status_t uct_bxi_get_txslot(uct_bxi_iface_t *iface, uint64_t **slot)
{
  struct ptlbxi_cq *q = &iface->dp.ni->dev->txq;
  int               used;

  for (;;) {
    used = (*q->tail - *q->head) & BXI_TX_PTRMASK;
    if (used >= BXI_CQ_LEN) {
      *q->head = *q->hw_head;
      used     = (*q->tail - *q->head) & BXI_TX_PTRMASK;
    }
    if (used >= BXI_CQ_LEN) {
      return UCS_ERR_NO_RESOURCE;
    }
  }

  *slot = (uint64_t *)(q->base + (*q->tail & BXI_CQ_MASK) * BXI_TX_SLOTSIZE);
  return UCS_OK;
}

static void uct_bxi_txslot_commit(uct_bxi_iface_t *iface)
{
  struct ptlbxi_cq *q = &iface->dp.ni->dev->txq;

  (*q->tail)++;

  /*
	 * ensure the command is not write combined
	 * with future commands and/or payload
	 */
  ucs_memory_bus_store_fence();
}

static void uct_bxi_txslot_set(uct_bxi_iface_t         *iface,
                               uct_bxi_iface_send_op_t *op, uint64_t *slot)
{
  struct ptlbxi_mddesc *mddesc = iface->super.tx.mdh.handle;
  unsigned int          id     = BXI_MAKEID(op->ep->dev_addr.pid.phys.nid,
                                            op->ep->dev_addr.pid.phys.pid);

  slot[0] = (uint64_t)id << BXI_TX0_DEST |
            (uint64_t)(PTL_NI_PHYSICAL | PTL_NI_MATCHING) << BXI_TX0_NI |
            (uint64_t)BXI_CMD_PUT << BXI_TX0_CMD | (uint64_t)1 << BXI_TX0_CNEW |
            (uint64_t)1 << BXI_TX0_CEND |
            (uint64_t)(op->length & 0xffff) << BXI_TX0_LENLO;
  slot[1] = (uint64_t)(op->length >> 16) << BXI_TX1_LENHI |
            (uint64_t)PTL_ACK_REQ << BXI_TX1_ACK |
            (uint64_t)mddesc->index << BXI_TX1_MD;
  slot[2] = (uint64_t)op->ep->iface_addr.am << BXI_TX2_PTE |
            (uint64_t)op->am.buffer << BXI_TX2_LOFFS;
  slot[3] = (uint64_t)op << BXI_TX3_UPTR;
  slot[4] = (uint64_t)0 << BXI_TX4_ROFFS | (uint64_t)iface->ni->dev->pid
                                                   << BXI_TX4_PID;
  slot[5] = (uint64_t)op->am.hdr << BXI_TX5_HDRDATA;
}

ucs_status_t uct_bxi_ep_dp_am_bcopy(uct_bxi_iface_t *iface, uct_bxi_ep_t *ep,
                                    uct_bxi_iface_send_op_t *op)
{
  ucs_status_t status;

  status = uct_bxidp_get_txslot(iface, &slot);
  if (status != UCS_OK) {
    goto err;
  }

  uct_bxidp_txslot_set(iface, op, slot);
  uct_bxidp_txslot_commit(iface);

err:
  return status;
}
