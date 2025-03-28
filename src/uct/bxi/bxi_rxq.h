#ifndef BXI_RQ_H
#define BXI_RQ_H

#include <uct/base/uct_iface.h>
#include <uct/bxi/bxi.h>

typedef struct uct_bxi_rxq uct_bxi_rxq_t;

typedef struct uct_bxi_recv_block {
  void           *start;
  size_t          size;
  uct_bxi_rxq_t  *rxq;
  ptl_handle_me_t meh;
  ucs_list_link_t elem;
  int             id;
} uct_bxi_recv_block_t;

typedef struct uct_bxi_rxq_param {
  uct_iface_mpool_config_t mp; /* RX Memory pool configuration. */
  ptl_size_t               min_free;
  ptl_list_t               list;
  char                    *name;
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
    int          num_blk;
  } config;
  ucs_mpool_t     mp;    /* Memory pool of block buffer */
  ucs_list_link_t bhead; /* List of allocated blocks */
} uct_bxi_rxq_t;

ucs_status_t uct_bxi_rxq_create(uct_bxi_iface_t     *iface,
                                uct_bxi_rxq_param_t *params,
                                uct_bxi_rxq_t      **rxq_p);
void         uct_bxi_rxq_fini(uct_bxi_rxq_t *rxq);

int uct_bxi_recv_block_activate(uct_bxi_recv_block_t *block);

static inline ptl_pt_index_t uct_bxi_rxq_get_addr(uct_bxi_rxq_t *rxq)
{
  return rxq->pti;
}

#endif
