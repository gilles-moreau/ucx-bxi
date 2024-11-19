#include "ptl_rma_ep.h"
#include "ptl_rma_ms.h"
#include "ptl_rma_iface.h"

#include <assert.h>

ecc_status_t ecr_ptl_rma_put_zcopy(ecr_ep_h ep, uint64_t local_addr,
                                   uint64_t remote_addr, ecr_mr_h mr,
                                   ecr_rkey_h rkey, size_t size,
                                   ecr_completion_t *comp)
{
    ecc_status_t      rc     = ECC_SUCCESS;
    ecr_ptl_rma_ep_t *ptl_ep = ecc_derived_of(ep, ecr_ptl_rma_ep_t);
    ecr_ptl_rma_mr_t *ptl_mr = ecc_derived_of(mr, ecr_ptl_rma_mr_t);
    ecr_ptl_op_t     *op     = ecc_mpool_pop(ptl_ep->ops);

    if (op == NULL) {
        ECC_LOG_WARNING("PTL: reached max outstanding operations.");
        rc = ECC_ERR_NORESOURCES;
        goto err;
    }

    op->comp = comp;
    op->size = size;
    op->seqn = ptl_mr->md.seqn++;

    rc = ecr_ptl_wrap(PtlPut(ptl_mr->md.mdh, (ptl_size_t)local_addr, size,
                             PTL_CT_ACK_REQ, ptl_ep->super.pid, ptl_ep->pti, 0,
                             remote_addr, NULL, 0));

    if (rc != ECC_SUCCESS) {
        ecc_mpool_push(op);
        size = ECC_ERR_INTERNAL;
        goto err;
    }

    ecc_queue_push(&ptl_mr->md.opq, &op->elem);

err:
    return rc;
}

ecc_status_t ecr_ptl_rma_get_zcopy(ecr_ep_h ep, uint64_t local_addr,
                                   uint64_t remote_addr, ecr_mr_h mr,
                                   ecr_rkey_h rkey, size_t size,
                                   ecr_completion_t *comp)
{
    ecc_status_t      rc     = ECC_SUCCESS;
    ecr_ptl_rma_ep_t *ptl_ep = ecc_derived_of(ep, ecr_ptl_rma_ep_t);
    ecr_ptl_rma_mr_t *ptl_mr = ecc_derived_of(mr, ecr_ptl_rma_mr_t);
    ecr_ptl_op_t     *op     = ecc_mpool_pop(ptl_ep->ops);

    if (op == NULL) {
        ECC_LOG_WARNING("PTL: reached max outstanding operations.");
        rc = ECC_ERR_NORESOURCES;
        goto err;
    }

    op->comp = comp;
    op->size = size;
    op->seqn = ptl_mr->md.seqn++;

    rc = ecr_ptl_wrap(PtlGet(ptl_mr->md.mdh, (ptl_size_t)local_addr, size,
                             ptl_ep->super.pid, ptl_ep->pti, 0, remote_addr,
                             NULL));

    if (rc != ECC_SUCCESS) {
        ecc_mpool_push(op);
        size = ECC_ERR_INTERNAL;
        goto err;
    }

    ecc_queue_push(&ptl_mr->md.opq, &op->elem);

err:
    return rc;
}


ECC_CLASS_DEFINE_INIT_FUNC(ecr_ptl_rma_ep_t, ecr_iface_h iface,
                           ecr_iface_addr_t *addr, unsigned flags)
{
    ecr_ptl_rma_iface_t *ptl_iface = ecc_derived_of(iface, ecr_ptl_rma_iface_t);
    ecr_ptl_rma_iface_addr_t *ptl_addr =
            ecc_derived_of(addr, ecr_ptl_rma_iface_addr_t);

    ECC_CLASS_CALL_SUPER_INIT(ecr_ptl_ep_t, self, iface, addr, flags);

    self->pti = ptl_addr->pti;

    self->ops = &ptl_iface->mp;

    return ECC_SUCCESS;
}

ECC_CLASS_DEFINE_CLEAN_FUNC(ecr_ptl_rma_ep_t)
{
    ECC_CLASS_CALL_SUPER_CLEAN(ecr_ptl_ep_t, self);
    return;
}

ECC_CLASS_DEFINE(ecr_ptl_rma_ep_t, ecr_ptl_ep_t);

ecc_status_t ecr_ptl_create_rma_ep(ecr_iface_h iface, ecr_iface_addr_t *addr,
                                   unsigned flags, ecr_ep_h *ep_p)
{
    ecc_status_t      rc;
    ecr_ptl_rma_ep_t *ep;

    rc = ECC_CLASS_NEW(ecr_ptl_rma_ep_t, &ep, iface, addr, flags);
    if (rc != ECC_SUCCESS)
        goto err;

    *ep_p = (ecr_ep_h)ep;

err:
    return rc;
}

ecc_status_t ecr_ptl_delete_rma_ep(ecr_ep_h ep)
{
    ECC_CLASS_DELETE(ecr_ptl_rma_ep_t, ep);

    return ECC_SUCCESS;
}
