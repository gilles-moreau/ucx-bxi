#ifndef PTL_RQ_H
#define PTL_RQ_H

#include <ecr/portals/ptl_types.h>
#include <ecc/datastruct/mpool.h>

enum {
    ECR_PTL_BLOCK_AM = PTL_ME_OP_PUT | PTL_ME_MANAGE_LOCAL |
                       PTL_ME_EVENT_LINK_DISABLE | PTL_ME_MAY_ALIGN |
                       PTL_ME_IS_ACCESSIBLE,
    ECR_PTL_BLOCK_TAG = PTL_ME_OP_PUT | PTL_ME_EVENT_LINK_DISABLE |
                        PTL_ME_MAY_ALIGN | PTL_ME_IS_ACCESSIBLE,
};

typedef struct ecr_ptl_recv_block {
    void           *start;
    size_t          size;
    ecr_ptl_rq_t   *rq;
    ptl_handle_me_t meh;
    ecc_list_elem_t elem;
    ecr_ptl_op_t    op;
} ecr_ptl_recv_block_t;

typedef struct ecr_ptl_rq_param {
    size_t       item_size;
    uint32_t     max_items;
    uint32_t     min_items;
    ptl_size_t   min_free;
    int          items_per_chunk;
    unsigned int options;
} ecr_ptl_rq_param_t;

typedef struct ecr_ptl_rq {
    ecr_ptl_iface_t *iface;
    struct {
        size_t       blk_size;
        unsigned int blk_opts;
        ptl_size_t   blk_min_free;
        int          num_blk;
    } config;
    ptl_pt_index_t  pti; // Portal Table Index of the receive queue
    ecc_mpool_t     mp; // Memory pool of block buffer
    ecc_list_elem_t bhead; // List of allocated blocks
    ptl_handle_eq_t eqh;
} ecr_ptl_rq_t;

ecc_status_t ecr_ptl_rq_init(ecr_ptl_iface_t *iface, ecr_ptl_rq_param_t *params,
                             ecr_ptl_rq_t *rq);
ecc_status_t ecr_ptl_rq_fini(ecr_ptl_rq_t *rq);

// Block operation
int ecr_ptl_recv_block_activate(ecr_ptl_recv_block_t *block);

#endif
