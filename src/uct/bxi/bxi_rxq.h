#ifndef BXI_RQ_H
#define BXI_RQ_H

#include "bxi.h"
#include <uct/base/uct_iface.h>

typedef struct uct_bxi_rxq        uct_bxi_rxq_t;
typedef struct uct_bxi_op_ctx     uct_bxi_op_ctx_t;
typedef struct uct_bxi_recv_block uct_bxi_recv_block_t;

typedef ucs_status_t (*uct_bxi_block_handler)(uct_bxi_iface_t      *iface,
                                              uct_bxi_recv_block_t *block,
                                              ptl_event_t          *ev);

enum {
  UCT_BXI_RECV_BLOCK_FLAG_IN_USE          = UCS_BIT(0),
  UCT_BXI_RECV_BLOCK_FLAG_RNDV            = UCS_BIT(1),
  UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOADED  = UCS_BIT(2),
  UCT_BXI_RECV_BLOCK_FLAG_COUNTER_ENABLED = UCS_BIT(3),
  UCT_BXI_RECV_BLOCK_FLAG_LINKED          = UCS_BIT(4),
  UCT_BXI_RECV_BLOCK_FLAG_INCREMENTED     = UCS_BIT(5),
};

typedef struct uct_bxi_recv_block_params {
  void            *start;
  size_t           size;
  ptl_process_t    pid;
  ptl_match_bits_t match;
  ptl_match_bits_t ign;
  unsigned         options;
  ptl_handle_ct_t  cth;
} uct_bxi_recv_block_params_t;

typedef struct uct_bxi_recv_block {
  unsigned              flags;
  const void           *orig;        /* Original address, GPU address */
  void                 *start;       /* Address of the receive block, may be 
                                        GDR mapped address for GPU mem */
  ssize_t               size;        /* Size of the receive block */
  size_t                send_size;   /* Actual size sent on the receive block */
  size_t                eager_limit; /* Cached eager limit for easy access 
                                        in release */
  uct_bxi_rxq_t        *rxq;         /* Back reference to the RX Queue */
  ucs_list_link_t       c_elem;      /* Element in the cancel list */
  uct_tag_t             tag;         /* Needed in case block is cancelled */
  uct_tag_t             stag;        /* Send tag */
  ucs_memory_type_t     mem_type;    /* Memory type of the buffer */
  ptl_list_t            list;     /* PTL_OVERFLOW_LIST or PTL_PRIORITY_LIST */
  uct_bxi_block_handler handler;  /* Receive block handler on event */
  uct_tag_context_t    *ctx;      /* Tag context provided by upper layer */
  ptl_handle_me_t       meh;      /* Memory Entry handle */
  ptl_handle_ct_t       cth;      /* Counter handle associated to 
                                        the block */
  ptl_handle_md_t       mdh;      /* Memory Descriptor used for GET */
  ptl_size_t            ct_value; /* SW counter tracking HW counter */
  uct_bxi_iface_send_op_t *op;    /* OP in case of GET protocol */
} uct_bxi_recv_block_t;

enum {
  UCT_BXI_RXQ_FLAG_EMPTY_MEMPOOL = UCS_BIT(1),
};

typedef struct uct_bxi_rxq_param {
  unsigned                 flags;    /* Flags to influence RXQ creation */
  uct_iface_mpool_config_t mp;       /* RX Memory pool configuration */
  ptl_list_t               list;     /* Portals priority list */
  char                    *name;     /* Name used of memory pool */
  uct_bxi_block_handler    handler;  /* Block handler called based on list */
  int                      num_segs; /* Number of segment per receive block */
  size_t                   seg_size; /* Segment size */
  ptl_handle_ni_t          nih;
  ptl_handle_eq_t          eqh;
} uct_bxi_rxq_param_t;

typedef struct uct_bxi_rxq {
  unsigned        flags;
  ptl_handle_ni_t nih;
  ptl_handle_eq_t eqh;
  ptl_pt_index_t  pti;  /* Portals Table Index for RX Queue */
  ptl_list_t      list; /* Portals list for blocks */
  struct {
    size_t       blk_size;
    unsigned int blk_opts;
    unsigned     num_blk;
  } config;
  ucs_mpool_t           mp;      /* Memory pool of block buffer */
  ucs_list_link_t       bhead;   /* List of allocated blocks */
  uct_bxi_block_handler handler; /* Block handler called based on list */
#if HAVE_PTL_LE_MANAGE_LOCAL
  ptl_le_t              unexp_le;
#else
  ptl_me_t              unexp_me;
#endif
} uct_bxi_rxq_t;

ucs_status_t uct_bxi_rxq_create(uct_bxi_rxq_param_t *params,
                                uct_bxi_rxq_t      **rxq_p);
void         uct_bxi_rxq_fini(uct_bxi_rxq_t *rxq);

void uct_bxi_recv_block_deactivate(uct_bxi_recv_block_t *block);
void uct_bxi_recv_block_release(uct_bxi_recv_block_t *block);

static UCS_F_ALWAYS_INLINE ptl_pt_index_t
uct_bxi_rxq_get_addr(uct_bxi_rxq_t *rxq)
{
  return rxq->pti;
}

static UCS_F_ALWAYS_INLINE ucs_status_t uct_bxi_recv_block_exp_activate(
        uct_bxi_rxq_t *rxq, uct_bxi_recv_block_t *block, ptl_me_t *me)
{
  ucs_status_t status;

  status = uct_bxi_wrap(
          PtlMEAppend(rxq->nih, rxq->pti, me, block->list, block, &block->meh));
  if (status != UCS_OK) {
    ucs_fatal("BXI: could not append ME");
  }

  return UCS_OK;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
uct_bxi_recv_block_unexp_activate(uct_bxi_recv_block_t *block)
{
  ucs_status_t   status;
  uct_bxi_rxq_t *rxq = block->rxq;

#if HAVE_PTL_LE_MANAGE_LOCAL
  rxq->unexp_le.start  = block->start;
  rxq->unexp_le.length = block->size;
  status = uct_bxi_wrap(PtlLEAppend(rxq->nih, rxq->pti, &rxq->unexp_le,
                                    block->list, block, &block->meh));
#else 
  rxq->unexp_me.start  = block->start;
  rxq->unexp_me.length = block->size;
  status = uct_bxi_wrap(PtlMEAppend(rxq->nih, rxq->pti, &rxq->unexp_me,
                                    block->list, block, &block->meh));
#endif

  if (status != UCS_OK) {
    ucs_fatal("BXI: could not append ME");
  }

  return UCS_OK;
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_recv_block_update_cnt(uct_bxi_recv_block_t *block, ptl_size_t inc)
{
  block->ct_value += inc;
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_recv_block_cancel_triggered(uct_bxi_recv_block_t *block)
{
  ucs_assert(!PtlHandleIsEqual(block->cth, PTL_CT_NONE));
  PtlCTCancelTriggered(block->cth);
}

#endif
