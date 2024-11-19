#include "ptl_rma_ms.h"

#include <ecr/portals/base/ptl_iface.h>

static ecc_config_entry_t ecr_ptl_rma_ms_config_entries[] = {
        {ECC_CONFIG_ELEM_ENTRY(super, "", "", ecr_ptl_rma_ms_config_t,
                               ECC_CONFIG_TYPE_TABLE(&ecr_ptl_ms_config_tab))},

        {""},
};

static ecc_config_tab_t ecr_ptl_rma_ms_config_tab = {
        "ECR_MS_RMA_PTL",
        ECC_LIST_INITIALIZER(NULL, NULL),
        ecr_ptl_rma_ms_config_entries,
        sizeof(ecr_ptl_rma_ms_config_t),
};

ecc_status_t ecr_ptl_rma_ms_reg_mem(ecr_ms_h ms, const void *addr, size_t size,
                                    ecr_mr_param_t *param, ecr_mr_h *mr_p)
{
    ecr_ptl_rma_mr_t *mr;
    ecc_status_t      rc     = ECC_SUCCESS;
    ecr_ptl_rma_ms_t *ptl_ms = ecc_derived_of(ms, ecr_ptl_rma_ms_t);
    ecr_ptl_iface_t  *ptl_iface;

    assert((param->field_mask & ECR_MR_FIELD_IFACE) && (param->iface != NULL));

    mr = (ecr_ptl_rma_mr_t *)malloc(sizeof(ecr_ptl_rma_mr_t));
    if (mr == NULL) {
        ECC_LOG_ERROR("PTL: could not allocate rma mr.");
        rc = ECC_ERR_OUT_OF_MEMORY;
        goto err;
    }
    mr->super.flags = 0;

    if (param->flags & (ECR_MR_FLAGS_LOCAL_READ | ECR_MR_FLAGS_LOCAL_WRITE)) {
        /* Memory descriptor for local access. */
        ecr_ptl_md_param_t md_param = (ecr_ptl_md_param_t){
                .flags = PTL_MD_EVENT_CT_ACK | PTL_MD_EVENT_CT_REPLY,
        };
        rc = ecr_ptl_ms_md_init(&ptl_ms->super, &md_param, &mr->md);
        if (rc != ECC_SUCCESS) {
            goto err;
        }
        mr->super.flags |= ECR_PTL_MR_FLAGS_INITIATOR;

        ptl_iface = ecc_derived_of(param->iface, ecr_ptl_iface_t);
        ecr_ptl_iface_enable_progression(ptl_iface, &mr->md);
    }

    if (param->flags & (ECR_MR_FLAGS_REMOTE_READ | ECR_MR_FLAGS_REMOTE_WRITE)) {
        assert(!PtlHandleIsEqual(ptl_ms->me.meh, PTL_INVALID_HANDLE));
        mr->me           = &ptl_ms->me;
        mr->super.flags |= ECR_PTL_MR_FLAGS_TARGET;
    }

    *mr_p = (ecr_mr_h)mr;

err:
    return rc;
}

ecc_status_t ecr_ptl_rma_ms_dereg_mem(ecr_ms_h ms, ecr_mr_h mr)
{
    ecc_status_t      rc     = ECC_SUCCESS;
    ecr_ptl_rma_mr_t *ptl_mr = (ecr_ptl_rma_mr_t *)mr;

    // TODO: add flags check to make sure it is an rma mr.

    if (ptl_mr->super.flags & ECR_PTL_MR_FLAGS_INITIATOR) {
        rc = ecr_ptl_ms_md_fini(&ptl_mr->md);
        if (rc != ECC_SUCCESS)
            goto err;

        ecr_ptl_iface_disable_progression(&ptl_mr->md);
    }

    free(mr);

err:
    return ECC_SUCCESS;
}

ECC_CLASS_DEFINE_INIT_FUNC(ecr_ptl_rma_ms_t, ecr_component_t *component,
                           ecr_device_t *dev, ecr_ptl_rma_ms_config_t *config)
{
    ecc_status_t rc;

    rc = ECC_CLASS_CALL_SUPER_INIT(ecr_ptl_ms_t, self, component, dev,
                                   &config->super);
    if (rc != ECC_SUCCESS)
        goto err;

    /* Memory entry for remote access. */
    ecr_ptl_me_param_t me_param = {
            .match  = 0,
            .ign    = ~0,
            .start  = NULL,
            .length = PTL_SIZE_MAX,
            .flags = PTL_ME_OP_PUT | PTL_ME_OP_GET | PTL_ME_EVENT_LINK_DISABLE |
                     PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_EVENT_SUCCESS_DISABLE,
    };
    rc = ecr_ptl_ms_me_init(&self->super, &me_param, &self->me);
    if (rc != ECC_SUCCESS)
        goto err;

err:
    return rc;
}

ECC_CLASS_DEFINE_CLEAN_FUNC(ecr_ptl_rma_ms_t)
{
    ecc_status_t rc;

    rc = ecr_ptl_ms_me_fini(&self->super, &self->me);
    if (rc != ECC_SUCCESS)
        goto err;

    ECC_CLASS_CALL_SUPER_CLEAN(ecr_ptl_ms_t, self);

err:
    return;
}

ECC_CLASS_DEFINE(ecr_ptl_rma_ms_t, ecr_ptl_ms_t);

void ecr_ptl_rma_ms_close(ecr_ms_h ms)
{
    ECC_CLASS_DELETE(ecr_ptl_rma_ms_t, ms);
}

ecc_status_t ecr_ptl_rma_ms_open(ecr_component_t *component, ecr_device_t *dev,
                                 const ecr_ms_config_t *cf, ecr_ms_h *ms_p)
{
    ecc_status_t             rc;
    ecr_ptl_rma_ms_t        *ptl_ms;
    ecr_ptl_rma_ms_config_t *config = ecc_derived_of(cf,
                                                     ecr_ptl_rma_ms_config_t);

    rc = ECC_CLASS_NEW(ecr_ptl_rma_ms_t, &ptl_ms, component, dev, config);
    if (rc != ECC_SUCCESS) {
        goto err;
    }

    ptl_ms->super.super.ops.reg_mem      = ecr_ptl_rma_ms_reg_mem;
    ptl_ms->super.super.ops.dereg_mem    = ecr_ptl_rma_ms_dereg_mem;
    ptl_ms->super.super.ops.pack_memkey  = ecr_ptl_ms_pack_memkey;
    ptl_ms->super.super.ops.unpack_rkey  = ecr_ptl_ms_unpack_rkey;
    ptl_ms->super.super.ops.release_rkey = ecr_ptl_ms_release_rkey;
    ptl_ms->super.super.ops.close        = ecr_ptl_rma_ms_close;

    *ms_p = (ecr_ms_h)ptl_ms;
err:
    return rc;
}


ecr_component_t ptl_rma_component = {
        .name          = {"ptl_rma"},
        .ms_open       = ecr_ptl_rma_ms_open,
        .query_devices = ecr_ptl_query_devices,
        .flags         = 0,
        .md_config =
                {
                        .cf      = &ecr_ptl_rma_ms_config_tab,
                        .cf_size = sizeof(ecr_ptl_ms_config_t),
                },
        .rails = ECC_LIST_INITIALIZER(&ptl_rma_component.rails,
                                      &ptl_rma_component.rails),
};
ECR_COMPONENT_REGISTER(&ptl_rma_component);
ECC_CONFIG_REGISTER(ecr_ptl_rma_ms_config_tab)
