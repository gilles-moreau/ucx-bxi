#ifndef PTL_RQ_H
#define PTL_RQ_H

#include <uct/bxi/ptl_types.h>

enum {
  ECR_PTL_BLOCK_AM = PTL_ME_OP_PUT | PTL_ME_MANAGE_LOCAL |
                     PTL_ME_EVENT_LINK_DISABLE | PTL_ME_MAY_ALIGN |
                     PTL_ME_IS_ACCESSIBLE,
  ECR_PTL_BLOCK_TAG = PTL_ME_OP_PUT | PTL_ME_EVENT_LINK_DISABLE |
                      PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_MAY_ALIGN |
                      PTL_ME_IS_ACCESSIBLE | PTL_ME_USE_ONCE,
};

#define UCT_PTL_RQ_NAME_LENGTH_MAX 24

typedef struct uct_ptl_recv_block {
  void           *start;
  size_t          size;
  uct_ptl_rq_t   *rq;
  ptl_handle_me_t meh;
  ucs_list_link_t elem;
  uct_ptl_op_t    op;
  int             id;
} uct_ptl_recv_block_t;

typedef struct uct_ptl_rq_param {
  size_t       item_size;
  uint32_t     max_items;
  uint32_t     min_items;
  ptl_size_t   min_free;
  int          items_per_chunk;
  unsigned int options;
  char         name[UCT_PTL_RQ_NAME_LENGTH_MAX];
} uct_ptl_rq_param_t;

typedef struct uct_ptl_rq {
  uct_ptl_iface_t *iface;
  struct {
    size_t       blk_size;
    unsigned int blk_opts;
    ptl_size_t   blk_min_free;
    int          num_blk;
  } config;
  ptl_pt_index_t  pti;   // Portal Table Index of the receive queue
  ucs_mpool_t     mp;    // Memory pool of block buffer
  ucs_list_link_t bhead; // List of allocated blocks
  ptl_handle_eq_t eqh;
  int             bid;
} uct_ptl_rq_t;

ucs_status_t uct_ptl_rq_init(uct_ptl_iface_t *iface, uct_ptl_rq_param_t *params,
                             uct_ptl_rq_t *rq);
void         uct_ptl_rq_fini(uct_ptl_rq_t *rq);

// Block operation
int uct_ptl_recv_block_activate(uct_ptl_recv_block_t *block);

#endif
