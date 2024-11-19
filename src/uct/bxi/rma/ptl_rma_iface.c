#include "ptl_rma_iface.h"
#include "ptl_rma_ep.h"
#include "ptl_rma_ms.h"

#include <ecr/portals/ptl_types.h>
#include <ecr/portals/base/ptl_rq.h>

static ecc_config_entry_t ecr_ptl_rma_iface_config_entries[] = {
        {ECC_CONFIG_ELEM_ENTRY(super, "", "", ecr_ptl_rma_iface_config_t,
                               ECC_CONFIG_TYPE_TABLE(
                                       &ecr_ptl_iface_config_tab))},

        {""},
};

static ecc_config_tab_t ecr_ptl_rma_iface_config_tab = {
        "ECR_IFACE_PTL_RMA",
        ECC_LIST_INITIALIZER(NULL, NULL),
        ecr_ptl_rma_iface_config_entries,
        sizeof(ecr_ptl_rma_iface_config_t),
};

ecc_status_t ecr_ptl_rma_iface_progress(ecr_iface_h super)
{
    ecc_status_t     rc;
    ecr_ptl_md_t    *md;
    ecr_ptl_iface_t *iface = ecc_derived_of(super, ecr_ptl_iface_t);

    ecc_list_for_each(md, &iface->mds, ecr_ptl_md_t, elem) {
        rc = ecr_ptl_md_progress(md);
        if (rc != ECC_SUCCESS)
            goto out;
    }

out:
    return rc;
}

static ecc_status_t ecr_ptl_rma_flush_iface(ecr_iface_h       iface,
                                            ecr_completion_t *comp,
                                            unsigned          flags)
{
    ecc_status_t         rc;
    ptl_size_t           last_seqn;
    ecr_ptl_md_t        *md;
    ecr_ptl_op_t        *op        = NULL;
    ecr_ptl_rma_iface_t *ptl_iface = ecc_derived_of(iface, ecr_ptl_rma_iface_t);

    /* Load the sequence number of the last rma operations. */
    ecc_list_for_each(md, &ptl_iface->super.mds, ecr_ptl_md_t, elem) {
        // TODO:  atomic load
        last_seqn = md->seqn - 1;

        rc = ecr_ptl_md_progress(md);
        if (rc != ECC_SUCCESS)
            goto err;

        if (!ecc_queue_is_empty(&md->opq)) {
            rc = ECC_INPROGRESS;

            op = ecc_mpool_pop(&ptl_iface->mp);
            if (op == NULL) {
                ECC_LOG_ERROR("PTL: could not allocate flush operation.");
                rc = ECC_ERR_OUT_OF_MEMORY;
                goto err;
            }
            op->comp = comp;
            op->seqn = last_seqn;

            // TODO: lock
            ecc_queue_push(&md->opq, &op->elem);
        }
    }

err:
    return rc;
}

static void ecr_ptl_iface_rma_close(ecr_iface_h iface)
{
    ECC_CLASS_DELETE(ecr_ptl_rma_iface_t, iface);
    return;
}

static void
ecr_ptl_rma_iface_get_addr(ecr_iface_h iface, ecr_iface_addr_t *addr)
{
    ecr_ptl_rma_iface_addr_t *ptl_addr =
            ecc_derived_of(addr, ecr_ptl_rma_iface_addr_t);
    ecr_ptl_rma_ms_t *ptl_ms = ecc_derived_of(iface->ms, ecr_ptl_rma_ms_t);

    ptl_addr->super.pid = ptl_ms->super.pid;
    ptl_addr->pti       = ptl_ms->me.idx;

    return;
}

ECC_CLASS_DEFINE_INIT_FUNC(ecr_ptl_rma_iface_t, ecr_ms_h ms,
                           ecr_device_t               *device,
                           ecr_ptl_rma_iface_config_t *config)
{
    ecc_status_t      rc = ECC_SUCCESS;
    ecc_mpool_param_t mp_ops_param;

    rc = ECC_CLASS_CALL_SUPER_INIT(ecr_ptl_iface_t, self, ms, device,
                                   &config->super);
    if (rc != ECC_SUCCESS) {
        goto err;
    }

    /* Set capabilities. */
    self->super.super.cap = ECR_IFACE_CAP_RMA;

    /* Work pool of operation. */
    mp_ops_param = (ecc_mpool_param_t){
            .elem_per_chunk = self->super.config.max_outstanding_ops,
            .min_elems      = 0,
            .max_elems      = self->super.config.max_outstanding_ops,
            .elem_size      = sizeof(ecr_ptl_op_t),
            .alignment      = 64,
            .free_func      = free,
            .malloc_func    = malloc,
    };
    rc = ecc_mpool_init(&self->mp, &mp_ops_param);
    if (rc != ECC_SUCCESS)
        goto err;

    self->super.super.iface_addr_size  = sizeof(ecr_ptl_rma_iface_addr_t);
    self->super.super.packed_rkey_size = 0;

err:
    return rc;
}

ECC_CLASS_DEFINE_CLEAN_FUNC(ecr_ptl_rma_iface_t)
{
    ecc_status_t  rc;
    ecr_ptl_md_t *md;

    // FIXME: this would mean a memory has not been unregistered... Not sure if
    // this should happen.
    ecc_list_for_each(md, &self->super.mds, ecr_ptl_md_t, elem) {
        rc = ecr_ptl_ms_md_fini(md);
        if (rc != ECC_SUCCESS)
            goto err;
    }

    ecc_mpool_fini(&self->mp);

    ECC_CLASS_CALL_SUPER_CLEAN(ecr_ptl_iface_t, self);
err:
    return;
}

ECC_CLASS_DEFINE(ecr_ptl_rma_iface_t, ecr_ptl_iface_t);

ecc_status_t ecr_ptl_rma_iface_open(ecr_ms_h ms, ecr_iface_config_t *config,
                                    ecr_iface_h *iface_p)
{
    ecc_status_t                rc = ECC_SUCCESS;
    ecr_ptl_iface_t            *ptl_iface;
    ecr_ptl_rma_iface_config_t *ptl_config =
            ecc_derived_of(config, ecr_ptl_rma_iface_config_t);

    rc = ECC_CLASS_NEW(ecr_ptl_rma_iface_t, &ptl_iface, ms, ms->dev,
                       ptl_config);
    if (rc != ECC_SUCCESS)
        goto err;

    ptl_iface->super.ops.put_zcopy      = ecr_ptl_rma_put_zcopy;
    ptl_iface->super.ops.get_zcopy      = ecr_ptl_rma_get_zcopy;
    ptl_iface->super.ops.flush_iface    = ecr_ptl_rma_flush_iface;
    ptl_iface->super.ops.iface_close    = ecr_ptl_iface_rma_close;
    ptl_iface->super.ops.iface_get_addr = ecr_ptl_rma_iface_get_addr;
    ptl_iface->super.ops.iface_get_attr = ecr_ptl_iface_get_attr;
    ptl_iface->super.ops.iface_progress = ecr_ptl_rma_iface_progress;
    ptl_iface->super.ops.ep_create      = ecr_ptl_create_rma_ep;
    ptl_iface->super.ops.ep_delete      = ecr_ptl_delete_rma_ep;

    *iface_p = (ecr_iface_t *)ptl_iface;
err:
    return rc;
}

ecr_rail_t ptl_rma_rail = {
        .name = "ptl_rma",
        .iface_config =
                {
                        .cf      = &ecr_ptl_rma_iface_config_tab,
                        .cf_size = sizeof(ecr_ptl_rma_iface_config_t),
                },
        .iface_open = ecr_ptl_rma_iface_open,
        .flags      = 0,
};
ECR_RAIL_REGISTER(&ptl_rma_component, &ptl_rma_rail);
ECC_CONFIG_REGISTER(ecr_ptl_rma_iface_config_tab);
