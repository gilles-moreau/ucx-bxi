#ifndef PTL_TAG_IFACE_H
#define PTL_TAG_IFACE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ecr/portals/base/ptl_iface.h>
#include <ecr/portals/base/ptl_rq.h>

#include <ecc/datastruct/mpool.h>

typedef struct ecr_ptl_tag_iface_addr {
    ecr_ptl_iface_addr_t super;
    ptl_pt_index_t       tag_pti;
    ptl_pt_index_t       rma_pti;
} ecr_ptl_tag_iface_addr_t;

typedef struct ecr_ptl_tag_iface_config {
    ecr_ptl_iface_config_t super;
    int                    id;
} ecr_ptl_tag_iface_config_t;

typedef struct ecr_ptl_tag_iface {
    ecr_ptl_iface_t super;
    struct {
        int id;
    } config;
    ecr_ptl_md_t  tag_md;
    ecr_ptl_md_t *rma_md;
    ecc_mpool_t   tag_mp;
    ecc_mpool_t   rma_mp;
    ecr_ptl_rq_t  rq;
} ecr_ptl_tag_iface_t;

ECC_CLASS_DECLARE_CLEAN_FUNC(ecr_ptl_tag_iface_t);

#endif
