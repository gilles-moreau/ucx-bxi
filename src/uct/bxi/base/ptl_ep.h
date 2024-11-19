#ifndef PTL_EP_H
#define PTL_EP_H

#include <ecr/portals/ptl_types.h>
#include <ecr/base/ecr_ep.h>

typedef struct ecr_ptl_ep_config {
    int id;
} ecr_ptl_ep_config_t;

typedef struct ecr_ptl_ep {
    ecr_ep_t super;
    struct {
        int id;
    } config;
    ptl_process_t pid;
} ecr_ptl_ep_t;

ECC_CLASS_DECLARE(ecr_ptl_ep_t);
ECC_CLASS_DECLARE_INIT_FUNC(ecr_ptl_ep_t, ecr_iface_h iface,
                            ecr_iface_addr_t *addr, unsigned flags);
ECC_CLASS_DECLARE_CLEAN_FUNC(ecr_ptl_ep_t);
#endif
