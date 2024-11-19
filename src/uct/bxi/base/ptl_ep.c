#include "ptl_ep.h"
#include "ptl_iface.h"

#include <ecr/portals/ptl_types.h>

#include <assert.h>

ECC_CLASS_DEFINE_INIT_FUNC(ecr_ptl_ep_t, ecr_iface_h iface,
                           ecr_iface_addr_t *addr, unsigned flags)
{
    ecc_status_t     rc;
    ecr_ptl_iface_t *ptl_iface = ecc_derived_of(iface, ecr_ptl_iface_t);

    rc = ECC_CLASS_CALL_SUPER_INIT(ecr_ep_t, self, iface, addr, flags);
    if (rc != ECC_SUCCESS)
        goto err;

    self->pid = ecr_ptl_iface_ms(ptl_iface)->pid;
err:
    return rc;
}

ECC_CLASS_DEFINE_CLEAN_FUNC(ecr_ptl_ep_t)
{
    ECC_CLASS_CALL_SUPER_CLEAN(ecr_ep_t, self);
    return;
}

ECC_CLASS_DEFINE(ecr_ptl_ep_t, ecr_ep_t);
