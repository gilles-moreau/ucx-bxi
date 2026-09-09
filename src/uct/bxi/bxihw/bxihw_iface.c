#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "bxihw_iface.h"
#include "bxihw_md.h"

#include <ucs/sys/ptr_arith.h>

#define UCT_BXIHW_MAX_EVENT 2048

#define UCT_BXIHW_PCB_ALIGN 1024
#define UCT_BXIHW_PCB_OFFSET(addr, base)                                       \
  (UCS_PTR_BYTE_DIFF(addr, base) / UCT_BXIHW_PCB_ALIGN)

#define UCT_BXIHW_EV_CLEAR(ev) (ev)->word[0] = 0;

int uct_bxihw_ev_copy(struct bxi_event *ev, uct_bxihw_ev_t *rev)
{
  uint64_t r, start;
  int      rc;

  /*
	 * For each word of the event, shift one by one each field to
	 * bit 0, mask it and store the result to the corresponding
	 * field.
	 *
	 * The compiler checks if we try to shift by a negative
	 * amount, so if one day field positions change the compiler
	 * will complain. No need to add compile time asserts about
	 * fields order.
	 */

  /* word 0 */
  r                         = ev->word[0] >> BXI_EV0_TYPE;
  rev->type                 = r & BXI_EVTYPE_MASK;
  r                       >>= (BXI_EV0_NIFAIL - BXI_EV0_TYPE);
  rev->ni_fail_type         = r & BXI_NIFAIL_MASK;
  r                       >>= (BXI_EV0_PTE - BXI_EV0_NIFAIL);
  rev->pt_index             = r & BXI_PTE_MASK;
  r                       >>= (BXI_EV0_AOP - BXI_EV0_PTE);
  rev->atomic_operation     = r & BXI_AOP_MASK;
  r                       >>= (BXI_EV0_ATYPE - BXI_EV0_AOP);
  rev->atomic_type          = r & BXI_ATYPE_MASK;
  r                       >>= (BXI_EV0_SRC - BXI_EV0_ATYPE);
  rev->initiator.phys.nid   = BXI_ID_GETNID(r & BXI_ID_MASK);
  rev->initiator.phys.pid   = BXI_ID_GETPID(r & BXI_ID_MASK);
  r                       >>= (BXI_EV0_LIST - BXI_EV0_SRC);
  rev->ptl_list             = r & 1;
  r                       >>= (BXI_EV0_DROPPED - BXI_EV0_LIST);
  rc                        = (r & 1) ? PTL_EQ_DROPPED : PTL_OK;

  /* word 1 */
  r                    = ev->word[1] >> BXI_EV1_ROFFS;
  rev->remote_offset   = r & BXI_ADDR_MASK;
  r                  >>= (BXI_EV1_STARTHI - BXI_EV1_ROFFS);
  start                = (r & BXI_EV_STARTHI_MASK) << 32;

  /* word 2 */
  r              = ev->word[2] >> BXI_EV2_MLEN;
  rev->mlength   = r & BXI_LENGTH_MASK;
  r            >>= (BXI_EV2_RLEN - BXI_EV2_MLEN);
  rev->rlength   = r & BXI_LENGTH_MASK;

  /* word 3 */
  rev->user_ptr = (void *)(ev->word[3] >> BXI_EV3_UPTR);

  /* word 4 */
  rev->uid = (ev->word[4] >> BXI_EV4_UID) & BXI_UID_MASK;

  /* word 5 */
  rev->hdr_data = ev->word[5] >> BXI_EV5_HDR;

  /* word 6 */
  rev->match_bits = ev->word[6] >> BXI_EV6_MATCHBITS;

  /* word 7 */
  start      |= (ev->word[7] >> BXI_EV7_STARTLO) & BXI_EV_STARTLO_MASK;
  rev->start  = (ptl_addr_t)start;

  return rc;
}

struct bxi_event *uct_bxihw_eq_get_ev(struct bxi_eq *eq)
{
  struct bxi_event *ev;
  uint64_t          start, head;

  start = (eq->reg0 >> BXI_EQ0_START) & BXI_EQSTART_MASK;
  head  = BXI_EQ_GET_HEAD(eq);
  ev    = (struct bxi_event *)((start + head) << 6);
  if (!BXI_EV_IS_VALID(ev))
    return NULL;

  ucs_memory_bus_load_fence();

  return ev;
}

void uct_bxihw_eq_discard_ev(struct bxi_eq *eq, struct bxi_event *ev)
{
  uint64_t *ev;
  uint64_t  start, head;
  int       order;

  start = (eq->reg0 >> BXI_EQ0_START) & BXI_EQSTART_MASK;
  order = (eq->reg0 >> BXI_EQ0_ORDER) & BXI_EQORDER_MASK;
  head  = BXI_EQ_GET_HEAD(eq);

  UCT_BXIHW_EV_CLEAR(ev);
  ucs_memory_bus_store_fence();

  head++;
  head &= (1ULL << order) - 1;
  BXI_EQ_SET_HEAD(eq, head);
}

int uct_bxihw_eq_get(uct_bxihw_iface_t *iface)
{
  int               rc;
  struct bxi_eq    *eq;
  struct bxi_event *ev;
  uct_bxihw_ev_t    rev;
  uint64_t          head;

  eq = iface->eq;
  ev = uct_bxihw_eq_get_ev(eq);
  if (ev == NULL) {
    ucs_debug("%s: %" PRIx64 ": empty\n", __func__, (uint64_t)eq);
    return PTL_EQ_EMPTY;
  }

  rc = uct_bxihw_ev_copy(ev, &rev);
  uct_bxihw_eq_discard_ev(eq, ev);

  return rc;
}

void *uct_bxihw_acquire_txslot(uct_bxihw_iface_t *iface)
{
  uct_bxihw_cq_t *cq = &iface->dev->txq;
  int             used;

  /*
	 * TX command queue uses 5-bit pointers (BXI_TX_PTRMASK) but has
	 * only 16 slots (BXI_CQ_MASK).
	 */
  used = (*cq->tail - *cq->head) & BXI_TX_PTRMASK;
  if (used >= BXI_CQ_LEN) {
    *cq->head = *cq->hw_head;
    used      = (*cq->tail - *cq->head) & BXI_TX_PTRMASK;
  }
  if (used >= BXI_CQ_LEN) {
    return NULL;
  }

  return cq->base + (*cq->tail & BXI_CQ_MASK) * BXI_TX_SLOTSIZE;
}

void uct_bxihw_commit_txslot(uct_bxihw_iface_t *iface)
{
  uct_bxihw_cq_t *cq = &iface->dev->txq;

  (*cq->tail)++;

  ucs_memory_bus_store_fence();
}

static ucs_status_t uct_bxihw_post_epucmd(uct_bxihw_iface_t *iface, int op,
                                          int handle)
{
}

static int uct_bxihw_eq_wait(uct_bxihw_iface_t *iface, int *rfail)
{
  struct bxi_event     *ev;
  uint64_t              r;
  struct bxi_eq        *eq = iface->eq;
  struct ptlbxi_medesc *me;
  struct ptl_listbuf   *lb;
  uint16_t             *meptr;
  int                   i, type, fail;
  int                   mei;

  for (;;) {
    ev = uct_bxihw_eq_get_ev(eq);
    if (ev == NULL)
      return 0;

    r    = ev->word[0];
    type = (r >> BXI_EV0_TYPE) & BXI_EVTYPE_MASK;
    fail = (r >> BXI_EV0_NIFAIL) & BXI_NIFAIL_MASK;
    if (type != BXI_EVTYPE_STATE_RETURN) {
      if (rfail == NULL) {
        /*
				 * don't steal another thread's
				 * completion event
				 */
        return 0;
      }
      /*
			 * at this point the only expected event
			 * is a completion
			 */
      *rfail = fail;
      break;
    }

    /*
		 * handle unsolicitated state-return events
		 */
    if ((r >> BXI_EV0_HOST) & 1) {
      mei = ((uint16_t *)ev)[BXI_EV_MES_START];

      me = ni->host_medesc + mei;
      lb = ni->listbuf + ptlbxi_hostme_listbuf(mei);
      LOGN(4, "%s: freeed me 0x%x\n", __func__, me->me_addr);
      me->next = lb->host_melist;
      me->incarnation++;
      lb->host_melist = me;
      lb->host_meavail++;
    } else if ((r >> BXI_EV0_CMD) & 1) {
      lb = ni->listbuf + ni->getmes_listbuf;
      if (fail == PTL_NI_OK) {
        meptr = (uint16_t *)ev + BXI_EV_MES_START;
        for (i = 0; i < BXI_EV_MES_COUNT; i++) {
          /*
					 * Rx behaves like described in HAS
					 * document. If state allocate is ok,
					 * bxi sends a event state return with
					 * ni_fail_type OK and all handles
					 * allocated. Otherwise a state return
					 * with ni_fail_type COMMAND_FAILED and
					 * all handles to zero.
					 */
          /*
					 * Update: 18 oct 2016: JIRA
					 * ticket BRIL-107 shows that we
					 * still get zero-handles on the
					 * ASIC. Ghassan suggested we
					 * ignore them; probably NIC
					 * counters indicate there are
					 * free handles, while there are
					 * none.
					 */

          mei = *meptr++;
          if (mei == 0) {
            LOG("%s: zero me[%d]\n", __func__, i);
            lb->getmes_skipcnt = BXI_EV_MES_COUNT;
            continue;
          }

          me       = ni->nic_medesc + mei;
          me->next = lb->nic_melist;
          me->incarnation++;
          lb->nic_melist = me;
          lb->nic_meavail++;
        }
      } else {
        LOGN(2,
             "%s: listbuf %d: getmes ni_fail_type"
             " = %d\n",
             __func__, ni->getmes_listbuf, fail);
        lb->getmes_skipcnt = BXI_EV_MES_COUNT;
      }
      ni->getmes_listbuf = -1;
    } else {
      mei = ((uint16_t *)ev)[BXI_EV_MES_START];
      if (mei == 0)
        ptlbxi_panic("ptlbxi_ni_waitret: zero nic me\n");
      if (type != BXI_EVTYPE_STATE_RETURN)
        ptlbxi_panic("ptlbxi_ni_waitret: bad async ev type\n");
      if (fail != PTL_NI_OK)
        ptlbxi_panic("ptlbxi_ni_waitret: bad async ev\n");
      me       = ni->nic_medesc + mei;
      lb       = ni->listbuf + ptlbxi_nicme_listbuf(mei);
      me->next = lb->nic_melist;
      me->incarnation++;
      lb->nic_melist = me;
      lb->nic_meavail++;
    }
    ptlbxi_eq_discard(ni->eq);
  }
  return 1;
}

static ucs_status_t uct_bxihw_eq_create(uct_bxihw_iface_t *iface)
{
  ucs_status_t   status = UCS_OK;
  int            ret;
  int            ord;
  size_t         size, rounded_ev_size;
  void          *start;
  struct bxi_eq *eq;

  ord = uct_bxihw_eq_order(UCT_BXIHW_MAX_EVENT);
  ucs_assert(ord >= 0);

  size            = BXI_EV_SIZE << ord;
  rounded_ev_size = (size + BXI_PAGESIZE - 1) & ~(BXI_PAGESIZE - 1);
  ret             = ucs_posix_memalign(&start, BXI_PAGESIZE, rounded_ev_size,
                                       "bxihw events");
  if (ret != 0) {
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }
  memset(start, 0, rounded_ev_size);

  eq       = iface->eq;
  eq->reg0 = ((uint64_t)start >> 6) << BXI_EQ0_START |
             (uint64_t)ord << BXI_EQ0_ORDER | (uint64_t)1 << BXI_EQ0_VALID;
  eq->reg1_lo  = 0;
  eq->reg1_hi  = (uint64_t)iface->vni << BXI_EQ1_HI_NI;
  eq->reg1_hi |= 0x7f << BXI_EQ1_HI_INTNO;

err:
  return status;
}

static ucs_status_t uct_bxihw_setup_pcb(uct_bxihw_iface_t *iface)
{
  ucs_status_t   status = UCS_OK;
  struct bxi_pcb pcb;
  int            phys;

  phys = 0;

  memset(&pcb, 0, sizeof(struct bxi_pcb));
  pcb.regs[0] = (uint64_t)iface->base << BXI_PCB0_BASE |
                (uint64_t)phys << BXI_PCB0_MEMMODE |
                (uint64_t)iface->vni << BXI_PCB0_NI |
                (uint64_t)1 << BXI_PCB0_VALID;
  pcb.regs[1] = (uint64_t)UCT_BXIHW_PCB_OFFSET(iface->md, iface->base)
                        << BXI_PCB1_MDOFFS |
                (uint64_t)iface->config.nmd << BXI_PCB1_MDSIZE |
                (uint64_t)UCT_BXIHW_PCB_OFFSET(iface->base_size, 0)
                        << BXI_PCB1_RANGE;
  pcb.regs[2] = (uint64_t)UCT_BXIHW_PCB_OFFSET(iface->ct, iface->base)
                        << BXI_PCB2_CTOFFS |
                (uint64_t)iface->config.nct << BXI_PCB2_CTSIZE |
                (uint64_t)UCT_BXIHW_PCB_OFFSET(iface->eq, iface->base)
                        << BXI_PCB2_EQOFFS |
                (uint64_t)iface->config.neq << BXI_PCB2_EQSIZE;
  pcb.regs[3] = (uint64_t)UCT_BXIHW_PCB_OFFSET(iface->me, iface->base)
                        << BXI_PCB3_MEOFFS |
                (uint64_t)UCT_BXIHW_PCB_OFFSET(iface->pt, iface->base)
                        << BXI_PCB3_PTOFFS |
                (uint64_t)UCT_BXIHW_PCB_OFFSET(iface->unex, iface->base)
                        << BXI_PCB3_UNEXOFFS |
                (uint64_t)UCT_BXIHW_PCB_OFFSET(iface->trig, iface->base)
                        << BXI_PCB3_TRIGOFFS;
  pcb.regs[4] = (uint64_t)0 << BXI_PCB4_RANK | (uint64_t)iface->dev->uid
                                                       << BXI_PCB4_UID;
  if (ioctl(iface->dev->fd, BXI_IOC_SETPCB, (unsigned long)&pcb) < 0) {
    ucs_error("BXI: BXI_IOC_SETPCB: %s\n", strerror(errno));
    status = UCS_ERR_IO_ERROR;
  }

  return status;
}

ucs_status_t uct_bxihw_iface_init(uct_md_h uct_md, uct_bxihw_iface_t **iface_p)
{
#define PCB_ROUND(x) ucs_align_up((x), UCT_BXIHW_PCB_ALIGN)
  ucs_status_t       status = UCS_OK;
  int                ret;
  uct_bxihw_iface_t *iface;
  uint64_t           base_size, rounded_base_size;
  void              *base;
  uct_bxihw_md_t    *md = (uct_bxihw_md_t *)uct_md;

  iface = ucs_malloc(sizeof(uct_bxihw_iface_t), "bxihw iface");
  if (iface == NULL) {
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }

  iface->dev = md;
  iface->vni = PTL_NI_PHYSICAL | PTL_NI_MATCHING;

  /* Set limits */
  iface->config.nsr   = 1;
  iface->config.nmd   = 1;
  iface->config.neq   = 1;
  iface->config.nct   = 0;
  iface->config.ntrig = 0;
  iface->config.nunex = 0;
  iface->config.nme   = 1;
  iface->config.npte  = 1;

  base_size = sizeof(uint64_t) * iface->config.nsr +
              PCB_ROUND(sizeof(struct bxi_md) * iface->config.nmd) +
              PCB_ROUND(sizeof(struct bxi_eq) * iface->config.neq) +
              PCB_ROUND(sizeof(struct bxi_ct) * iface->config.nct) +
              PCB_ROUND(sizeof(struct bxi_trig) * iface->config.ntrig) +
              PCB_ROUND(sizeof(struct bxi_me) * iface->config.nunex) +
              PCB_ROUND(sizeof(struct bxi_pte) * BXI_NPTE) +
              PCB_ROUND(sizeof(struct bxi_me) * iface->config.nme);

  rounded_base_size = (base_size + BXI_PAGESIZE - 1) & ~(BXI_PAGESIZE - 1);
  ret               = ucs_posix_memalign(&base, BXI_PAGESIZE, rounded_base_size,
                                         "bxihw base");
  if (ret != 0) {
    status = UCS_ERR_NO_MEMORY;
    goto err_free_iface;
  }

  iface->base      = base;
  iface->base_size = base_size;
  memset(iface->base, 0, base_size);

  iface->sr = base;
  iface->md = UCS_PTR_BYTE_OFFSET(
          iface->sr, PCB_ROUND(sizeof(uint64_t) * iface->config.nsr));
  iface->eq = UCS_PTR_BYTE_OFFSET(
          iface->md, PCB_ROUND(sizeof(struct bxi_md) * iface->config.nmd));
  iface->ct = UCS_PTR_BYTE_OFFSET(
          iface->eq, PCB_ROUND(sizeof(struct bxi_eq) * iface->config.neq));
  iface->trig = UCS_PTR_BYTE_OFFSET(
          iface->ct, PCB_ROUND(sizeof(struct bxi_ct) * iface->config.nct));
  iface->unex =
          UCS_PTR_BYTE_OFFSET(iface->trig, PCB_ROUND(sizeof(struct bxi_trig) *
                                                     iface->config.ntrig));
  iface->pt = UCS_PTR_BYTE_OFFSET(
          iface->unex, PCB_ROUND(sizeof(struct bxi_me) * iface->config.nunex));
  iface->me = UCS_PTR_BYTE_OFFSET(iface->pt,
                                  PCB_ROUND(sizeof(struct bxi_pte) * BXI_NPTE));

  /* Setup pcb on the nic */
  status = uct_bxihw_setup_pcb(iface);
  if (status != UCS_OK) {
    goto err_free_iface;
  }

  /* Create event queue */
  status = uct_bxihw_eq_create(iface);
  if (status != UCS_OK) {
    goto err_free_base;
  }

  *iface_p = iface;
  return status;

err_free_base:
  ucs_free(base);
err_free_iface:
  ucs_free(iface);
err:
  return status;
}
