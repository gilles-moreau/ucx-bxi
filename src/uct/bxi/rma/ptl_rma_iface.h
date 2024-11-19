#ifndef PTL_RMA_IFACE_H
#define PTL_RMA_IFACE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ecr/portals/base/ptl_iface.h>
#include <ecr/portals/base/ptl_rq.h>

#include <ecc/datastruct/mpool.h>

typedef struct ecr_ptl_rma_iface_addr {
    ecr_ptl_iface_addr_t super;
    ptl_pt_index_t       pti;
} ecr_ptl_rma_iface_addr_t;

typedef struct ecr_ptl_rma_iface_config {
    ecr_ptl_iface_config_t super;
    int                    id;
} ecr_ptl_rma_iface_config_t;

typedef struct ecr_ptl_rma_iface {
    ecr_ptl_iface_t super;
    struct {
        int id;
    } config;
    ecc_mpool_t mp;
} ecr_ptl_rma_iface_t;

ECC_CLASS_DECLARE_CLEAN_FUNC(ecr_ptl_rma_iface_t);

#endif
