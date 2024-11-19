#ifndef PTL_AM_IFACE_H
#define PTL_AM_IFACE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ecr/portals/base/ptl_iface.h>
#include <ecr/portals/base/ptl_rq.h>

#include <ecc/datastruct/mpool.h>

#define ECR_PTL_HDR_ID_MASK 0x00000000000000ffULL

#define ECR_PTL_HDR_GET_AM_ID(_hdr) ((uint8_t)(_hdr & ECR_PTL_HDR_ID_MASK))

#define ECR_PTL_HDR_SET(_hdr, _am_id) (_hdr = (_am_id & 0xff))

typedef struct ecr_ptl_am_iface_addr {
    ecr_ptl_iface_addr_t super;
    ptl_pt_index_t       am_pti;
    ptl_pt_index_t       rma_pti;
} ecr_ptl_am_iface_addr_t;

typedef struct ecr_ptl_am_iface_config {
    ecr_ptl_iface_config_t super;
    int                    id;
} ecr_ptl_am_iface_config_t;

typedef struct ecr_ptl_am_iface {
    ecr_ptl_iface_t super;
    struct {
        int id;
    } config;
    ecr_ptl_md_t  am_md;
    ecr_ptl_md_t *rma_md;
    ecc_mpool_t   am_mp;
    ecc_mpool_t   rma_mp;
    ecr_ptl_rq_t  rq;
} ecr_ptl_am_iface_t;

ECC_CLASS_DECLARE_CLEAN_FUNC(ecr_ptl_am_iface_t);

#endif
