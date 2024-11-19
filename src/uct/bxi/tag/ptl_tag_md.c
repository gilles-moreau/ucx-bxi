#include "ptl_tag_ms.h"

static ecc_config_entry_t ecr_ptl_tag_ms_config_entries[] = {
        {ECC_CONFIG_ELEM_ENTRY(super, "", "", ecr_ptl_tag_ms_config_t,
                               ECC_CONFIG_TYPE_TABLE(&ecr_ptl_ms_config_tab))},

        {""},
};

static ecc_config_tab_t ecr_ptl_tag_ms_config_tab = {
        "ECR_MS_TAG_PTL",
        ECC_LIST_INITIALIZER(NULL, NULL),
        ecr_ptl_tag_ms_config_entries,
        sizeof(ecr_ptl_tag_ms_config_t),
};

ecc_status_t ecr_ptl_tag_ms_reg_mem(ecr_ms_h ms, const void *addr, size_t size,
                                    ecr_mr_param_t *param, ecr_mr_h *mr_p)
{
    ecr_ptl_tag_mr_t *mr;
    ecc_status_t      rc     = ECC_SUCCESS;
    ecr_ptl_tag_ms_t *ptl_ms = ecc_derived_of(ms, ecr_ptl_tag_ms_t);

    mr = (ecr_ptl_tag_mr_t *)malloc(sizeof(ecr_ptl_tag_mr_t));
    if (mr == NULL) {
        ECC_LOG_ERROR("PTL: could not allocate tag mr.");
        rc = ECC_ERR_OUT_OF_MEMORY;
        goto err;
    }
    mr->super.flags = 0;

    if (param->flags & (ECR_MR_FLAGS_LOCAL_READ | ECR_MR_FLAGS_LOCAL_WRITE)) {
        assert(!PtlHandleIsEqual(ptl_ms->md.mdh, PTL_INVALID_HANDLE));
        mr->md           = &ptl_ms->md;
        mr->super.flags |= ECR_PTL_MR_FLAGS_INITIATOR;
    }

    if (param->flags & (ECR_MR_FLAGS_REMOTE_READ | ECR_MR_FLAGS_REMOTE_WRITE)) {
        mr->me.match  = ptl_ms->me_mb++;
        mr->me.offset = (uint64_t)addr;

        ecr_ptl_me_param_t me_param = {
                .match  = mr->me.match,
                .ign    = 0,
                .start  = (void *)addr,
                .length = size,
                .flags  = PTL_ME_OP_PUT | PTL_ME_OP_GET |
                         PTL_ME_EVENT_LINK_DISABLE |
                         PTL_ME_EVENT_UNLINK_DISABLE |
                         PTL_ME_EVENT_COMM_DISABLE,
        };

        rc = ecr_ptl_ms_me_init(&ptl_ms->super, &me_param, &mr->me);
        if (rc != ECC_SUCCESS) {
            goto err;
        }

        mr->super.flags |= ECR_PTL_MR_FLAGS_TARGET;
    }

    *mr_p = (ecr_mr_h)mr;

err:
    return rc;
}

ecc_status_t ecr_ptl_tag_ms_dereg_mem(ecr_ms_h ms, ecr_mr_h mr)
{
    ecc_status_t      rc     = ECC_SUCCESS;
    ecr_ptl_tag_mr_t *ptl_mr = (ecr_ptl_tag_mr_t *)mr;
    ecr_ptl_tag_ms_t *ptl_ms = ecc_derived_of(ms, ecr_ptl_tag_ms_t);

    /* Nothing to be done for MD.*/

    /* Unlink ME.*/
    if (ptl_mr->super.flags & ECR_PTL_MR_FLAGS_TARGET) {
        rc = ecr_ptl_ms_me_fini(&ptl_ms->super, &ptl_mr->me);
        if (rc != ECC_SUCCESS) {
            goto err;
        }
    }

    free(mr);
err:

    return rc;
}

ecc_status_t ecr_ptl_tag_ms_pack_memkey(ecr_ms_h ms, ecr_mr_h mr, void *dest)
{
    ecr_ptl_tag_mr_t *ptl_mr = (ecr_ptl_tag_mr_t *)mr;
    void             *p      = dest;

    ecc_serialize(p, ptl_match_bits_t, ptl_mr->me.match);
    ecc_serialize(p, uint64_t, ptl_mr->me.offset);

    return ECC_SUCCESS;
}

ecc_status_t ecr_ptl_tag_ms_unpack_rkey(ecr_ms_h ms, const void *rkey_buffer,
                                        ecr_rkey_h *rkey_p)
{
    ecc_status_t        rc = ECC_SUCCESS;
    ecr_ptl_tag_rkey_t *rkey;
    void               *p = (void *)rkey_buffer;

    rkey = malloc(sizeof(ecr_ptl_tag_rkey_t));
    if (rkey == NULL) {
        ECC_LOG_ERROR("Could not allocate tag remote key.");
        rc = ECC_ERR_OUT_OF_MEMORY;
        goto err;
    }
    rkey->super.dummy = 'c';

    ecc_deserialize(p, ptl_match_bits_t, rkey->match);
    ecc_deserialize(p, uint64_t, rkey->offset);

    *rkey_p = (ecr_rkey_h)rkey;
err:
    return rc;
}

ECC_CLASS_DEFINE_INIT_FUNC(ecr_ptl_tag_ms_t, ecr_component_t *component,
                           ecr_device_t *dev, ecr_ptl_tag_ms_config_t *config)
{
    ecc_status_t       rc;
    ecr_ptl_md_param_t md_param;

    rc = ECC_CLASS_CALL_SUPER_INIT(ecr_ptl_ms_t, self, component, dev,
                                   &config->super);
    if (rc != ECC_SUCCESS)
        goto err;

    /* Memory descriptor for local access. */
    md_param = (ecr_ptl_md_param_t){
            .flags = PTL_MD_EVENT_CT_ACK | PTL_MD_EVENT_CT_REPLY,
    };
    rc = ecr_ptl_ms_md_init(&self->super, &md_param, &self->md);
    if (rc != ECC_SUCCESS)
        goto err;

    /* Initialize matching sequence number. */
    self->me_mb = 0;
err:
    return rc;
}

ECC_CLASS_DEFINE_CLEAN_FUNC(ecr_ptl_tag_ms_t)
{
    ECC_CLASS_CALL_SUPER_CLEAN(ecr_ptl_ms_t, self);

    return;
}

ECC_CLASS_DEFINE(ecr_ptl_tag_ms_t, ecr_ptl_ms_t);

void ecr_ptl_tag_ms_close(ecr_ms_h ms)
{
    ECC_CLASS_DELETE(ecr_ptl_tag_ms_t, ms);
}

ecc_status_t ecr_ptl_tag_ms_open(ecr_component_t *component, ecr_device_t *dev,
                                 const ecr_ms_config_t *cf, ecr_ms_h *ms_p)
{
    ecc_status_t             rc;
    ecr_ptl_tag_ms_t        *ptl_ms;
    ecr_ptl_tag_ms_config_t *config = ecc_derived_of(cf,
                                                     ecr_ptl_tag_ms_config_t);

    rc = ECC_CLASS_NEW(ecr_ptl_tag_ms_t, &ptl_ms, component, dev, config);
    if (rc != ECC_SUCCESS) {
        goto err;
    }

    ptl_ms->super.super.ops.reg_mem      = ecr_ptl_tag_ms_reg_mem;
    ptl_ms->super.super.ops.dereg_mem    = ecr_ptl_tag_ms_dereg_mem;
    ptl_ms->super.super.ops.pack_memkey  = ecr_ptl_tag_ms_pack_memkey;
    ptl_ms->super.super.ops.unpack_rkey  = ecr_ptl_tag_ms_unpack_rkey;
    ptl_ms->super.super.ops.release_rkey = ecr_ptl_ms_release_rkey;
    ptl_ms->super.super.ops.close        = ecr_ptl_tag_ms_close;

    *ms_p = (ecr_ms_h)ptl_ms;
err:
    return rc;
}


ecr_component_t ptl_tag_component = {
        .name          = {"ptl_tag"},
        .ms_open       = ecr_ptl_tag_ms_open,
        .query_devices = ecr_ptl_query_devices,
        .flags         = 0,
        .md_config =
                {
                        .cf      = &ecr_ptl_tag_ms_config_tab,
                        .cf_size = sizeof(ecr_ptl_ms_config_t),
                },
        .rails = ECC_LIST_INITIALIZER(&ptl_tag_component.rails,
                                      &ptl_tag_component.rails),
};
ECR_COMPONENT_REGISTER(&ptl_tag_component);
ECC_CONFIG_REGISTER(ecr_ptl_tag_ms_config_tab)
