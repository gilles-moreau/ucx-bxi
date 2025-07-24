#ifndef BXI_RQ_H
#define BXI_RQ_H

#include <uct/base/uct_iface.h>
#include <uct/bxi/bxi.h>

typedef struct uct_bxi_rxq    uct_bxi_rxq_t;
typedef struct uct_bxi_op_ctx uct_bxi_op_ctx_t;

typedef ucs_status_t (*uct_bxi_rxq_ev_handler)(uct_bxi_iface_t *iface,
                                               ptl_event_t     *ev);

enum {
  UCT_BXI_RECV_BLOCK_FLAG_HAS_TRIGOP   = UCS_BIT(0),
  UCT_BXI_RECV_BLOCK_FLAG_UPDATE_CNT   = UCS_BIT(1),
  UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOAD = UCS_BIT(2)
};

typedef struct uct_bxi_recv_block_params {
  void            *start;
  size_t           size;
  ptl_match_bits_t match;
  ptl_match_bits_t ign;
  unsigned         options;
  ptl_handle_ct_t  cth;
} uct_bxi_recv_block_params_t;

typedef struct uct_bxi_block_cnt {
  ptl_handle_ct_t cth;
  ptl_size_t      threshold;
} uct_bxi_block_cnt_t;

typedef struct uct_bxi_recv_block {
  unsigned            flags;
  void               *start;       /* Address of the receive block */
  size_t              size;        /* Size of the receive block */
  size_t              send_size;   /* Actual size sent on the receive block */
  size_t              eager_limit; /* Eager limit */
  uct_bxi_rxq_t      *rxq;         /* Back reference to the RX Queue */
  ptl_handle_me_t     meh;         /* Memory Entry handle */
  ucs_list_link_t     elem;        /* Element in the RX Queue */
  ucs_list_link_t     c_elem;      /* Element in the cancel list */
  uct_tag_t           tag;         /* Needed in case block is cancelled */
  uct_tag_t           stag;        /* Send tag */
  ptl_list_t          list;        /* Portals list: OVERFLOW or PRIORITY */
  uct_tag_context_t  *ctx;         /* Tag context provided by upper layer */
  uct_bxi_block_cnt_t cnt;
  ptl_handle_ct_t     cth;     /* Counter associated when recv if offloaded */
  uct_bxi_iface_send_op_t *op; /* OP in case of GET protocol */
} uct_bxi_recv_block_t;

enum {
  UCT_BXI_RXQ_FLAG_EMPTY_MEMPOOL = UCS_BIT(1),
};

typedef struct uct_bxi_rxq_param {
  unsigned                 flags;    /* Flags to influence RXQ creation */
  uct_iface_mpool_config_t mp;       /* RX Memory pool configuration */
  ptl_list_t               list;     /* Portals priority list */
  char                    *name;     /* Name used of memory pool */
  uct_bxi_rxq_ev_handler   handler;  /* Event handler called when polling RX */
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
    ptl_size_t   blk_min_free;
    unsigned     num_blk;
  } config;
  ucs_mpool_t            mp;      /* Memory pool of block buffer */
  ucs_list_link_t        bhead;   /* List of allocated blocks */
  uct_bxi_rxq_ev_handler handler; /* Event handler when RXQ is polled. */
} uct_bxi_rxq_t;

ucs_status_t uct_bxi_rxq_create(uct_bxi_iface_t     *iface,
                                uct_bxi_rxq_param_t *params,
                                uct_bxi_rxq_t      **rxq_p);
void         uct_bxi_rxq_fini(uct_bxi_rxq_t *rxq);

ucs_status_t uct_bxi_recv_block_activate(uct_bxi_recv_block_t        *block,
                                         uct_bxi_recv_block_params_t *params);
void         uct_bxi_recv_block_deactivate(uct_bxi_recv_block_t *block);
void         uct_bxi_recv_block_release(uct_bxi_recv_block_t *block);

static inline ptl_pt_index_t uct_bxi_rxq_get_addr(uct_bxi_rxq_t *rxq)
{
  return rxq->pti;
}

static UCS_F_ALWAYS_INLINE int
uct_bxi_recv_block_is_unexpected(uct_bxi_recv_block_t *block)
{
  return block->list == PTL_OVERFLOW_LIST;
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_recv_block_update_cnt_thresh(uct_bxi_recv_block_t *block,
                                     ptl_size_t            mlength)
{
  if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_UPDATE_CNT)
    block->cnt.threshold -= block->eager_limit + 1 - mlength;
}

#endif
