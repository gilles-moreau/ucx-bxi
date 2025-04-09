#ifndef BXI_RQ_H
#define BXI_RQ_H

#include <uct/base/uct_iface.h>
#include <uct/bxi/bxi.h>

typedef struct uct_bxi_rxq uct_bxi_rxq_t;

typedef ucs_status_t (*uct_bxi_rxq_ev_handler)(uct_bxi_iface_t *iface,
                                               ptl_event_t     *ev);

typedef struct uct_bxi_recv_block_params {
  void            *start;
  size_t           size;
  ptl_match_bits_t match;
  ptl_match_bits_t ign;
  unsigned         options;
  ptl_handle_ct_t  cth;
} uct_bxi_recv_block_params_t;

typedef struct uct_bxi_recv_block {
  void                    *start; /* Address of the receive block */
  size_t                   size;  /* Size of the receive block */
  uct_bxi_rxq_t           *rxq;   /* Back reference to the RX Queue */
  ptl_handle_me_t          meh;   /* Memory Entry handle */
  ucs_list_link_t          elem;  /* Element in the RX Queue */
  ptl_list_t               list;  /* Portals list */
  uct_tag_context_t       *ctx;   /* Tag context provided by upper layer */
  uct_tag_t                tag;   /* Tag used for offloaded matchin */
  uct_bxi_iface_send_op_t *op;    /* OP in case of GET protocol */
} uct_bxi_recv_block_t;

typedef struct uct_bxi_rxq_param {
  uct_iface_mpool_config_t mp;       /* RX Memory pool configuration */
  ptl_size_t               min_free; /* Minimum size before block is unlinked */
  ptl_list_t               list;     /* Portals priority list */
  char                    *name;     /* Name used of memory pool */
  uct_bxi_rxq_ev_handler   handler;  /* Event handler called when polling RX */
  ptl_handle_ni_t          nih;
  ptl_handle_eq_t          eqh;
} uct_bxi_rxq_param_t;

typedef struct uct_bxi_rxq {
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

static inline ptl_pt_index_t uct_bxi_rxq_get_addr(uct_bxi_rxq_t *rxq)
{
  return rxq->pti;
}

#endif
