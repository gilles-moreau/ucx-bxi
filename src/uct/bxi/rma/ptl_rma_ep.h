#ifndef PTL_RMA_EP_H
#define PTL_RMA_EP_H

#include <ecr/portals/base/ptl_ep.h>
#include <ecr/portals/ptl_types.h>

#include <ecc/datastruct/mpool.h>

typedef struct ecr_ptl_rma_ep_config {
    int id;
} ecr_ptl_rma_ep_config_t;

typedef struct ecr_ptl_rma_ep {
    ecr_ptl_ep_t super;
    struct {
        int id;
    } config;
    ptl_pt_index_t pti;
    ecc_mpool_t   *ops;
} ecr_ptl_rma_ep_t;

ecc_status_t ecr_ptl_rma_put_zcopy(ecr_ep_h ep, uint64_t local_addr,
                                   uint64_t remote_addr, ecr_mr_h mr,
                                   ecr_rkey_h rkey, size_t size,
                                   ecr_completion_t *comp);
ecc_status_t ecr_ptl_rma_get_zcopy(ecr_ep_h ep, uint64_t local_addr,
                                   uint64_t remote_addr, ecr_mr_h mr,
                                   ecr_rkey_h rkey, size_t size,
                                   ecr_completion_t *comp);
ecc_status_t ecr_ptl_create_rma_ep(ecr_iface_h iface, ecr_iface_addr_t *addr,
                                   unsigned flags, ecr_ep_h *ep_p);
ecc_status_t ecr_ptl_delete_rma_ep(ecr_ep_h ep);

#endif
