#include "ptl_am_iface.h"
#include "ptl_am_ms.h"
#include "ptl_am_ep.h"

#include <ecr/portals/ptl_types.h>
#include <ecr/portals/base/ptl_rq.h>

static ecc_config_entry_t ecr_ptl_am_iface_config_entries[] = {
        {ECC_CONFIG_ELEM_ENTRY(super, "", "", ecr_ptl_am_iface_config_t,
                               ECC_CONFIG_TYPE_TABLE(
                                       &ecr_ptl_iface_config_tab))},

        {""},
};

static ecc_config_tab_t ecr_ptl_am_iface_config_tab = {
        "ECR_IFACE_PTL_AM",
        ECC_LIST_INITIALIZER(NULL, NULL),
        ecr_ptl_am_iface_config_entries,
        sizeof(ecr_ptl_am_iface_config_t),
};

static ecc_status_t
ecr_ptl_am_iface_handle_ev(ecr_ptl_iface_t *iface, ptl_event_t *ev)
{
    ecc_status_t          rc = ECC_SUCCESS;
    uint8_t               am_id;
    ecr_ptl_recv_block_t *block;

    ECC_LOG_INFO("PORTALS: EQS EVENT '%s' eqh=%llu, idx=%d, "
                 "sz=%llu, user=%p, start=%p, "
                 "remote_offset=%llu, iface=%llu",
                 ecr_ptl_event_str[ev->type], iface->eqh, ev->pt_index,
                 ev->mlength, ev->user_ptr, ev->start, ev->remote_offset, 0);

    switch (ev->type) {
    case PTL_EVENT_PUT_OVERFLOW:
    case PTL_EVENT_PUT:
        /* First, invoke AM handle. */
        am_id = ECR_PTL_HDR_GET_AM_ID(ev->hdr_data);
        rc = ecr_iface_invoke_am(&iface->super, am_id, ev->mlength, ev->start,
                                 0);
        break;
    case PTL_EVENT_AUTO_UNLINK:
        block = (ecr_ptl_recv_block_t *)ev->user_ptr;
        rc    = ecr_ptl_recv_block_activate(block);
        break;

    case PTL_EVENT_LINK:
    case PTL_EVENT_GET_OVERFLOW:
    case PTL_EVENT_GET:
    case PTL_EVENT_AUTO_FREE:
    case PTL_EVENT_ACK:
    case PTL_EVENT_ATOMIC:
    case PTL_EVENT_FETCH_ATOMIC:
    case PTL_EVENT_SEARCH:
    case PTL_EVENT_SEND:
    case PTL_EVENT_REPLY:
    case PTL_EVENT_FETCH_ATOMIC_OVERFLOW:
    case PTL_EVENT_ATOMIC_OVERFLOW:
        ECC_LOG_ERROR("PTL: event %s should not have been triggered",
                      ecr_ptl_event_str[ev->type]);
        rc = ECC_ERR_INTERNAL;
        break;
    case PTL_EVENT_PT_DISABLED:
        ECC_LOG_ERROR("PTL: control flow not implemented.");
        rc = ECC_ERR_INTERNAL;
        break;
    default:
        break;
    }

    return rc;
}

static ecc_status_t ecr_ptl_am_flush_iface(ecr_iface_h       iface,
                                           ecr_completion_t *comp,
                                           unsigned          flags)
{
    ecc_status_t        rc;
    ptl_size_t          last_seqn;
    ecr_ptl_op_t       *op        = NULL;
    ecr_ptl_am_iface_t *ptl_iface = ecc_derived_of(iface, ecr_ptl_am_iface_t);

    /* Load the sequence number of the last rma operations. */
    // TODO:  atomic load
    last_seqn = ptl_iface->rma_md->seqn - 1;

    rc = ecr_ptl_md_progress(ptl_iface->rma_md);
    if (rc != ECC_SUCCESS)
        goto err;

    if (!ecc_queue_is_empty(&ptl_iface->rma_md->opq)) {
        rc = ECC_INPROGRESS;

        op = ecc_mpool_pop(&ptl_iface->rma_mp);
        if (op == NULL) {
            ECC_LOG_ERROR("PTL: could not allocate flush operation.");
            rc = ECC_ERR_OUT_OF_MEMORY;
            goto err;
        }
        op->comp = comp;
        op->seqn = last_seqn;

        // TODO: lock
        ecc_queue_push(&ptl_iface->rma_md->opq, &op->elem);
    }

err:
    return rc;
}


static void ecr_ptl_iface_am_close(ecr_iface_h iface)
{
    ECC_CLASS_DELETE(ecr_ptl_am_iface_t, iface);
    return;
}

static void ecr_ptl_am_iface_get_addr(ecr_iface_h iface, ecr_iface_addr_t *addr)
{
    ecr_ptl_am_iface_addr_t *ptl_addr = ecc_derived_of(addr,
                                                       ecr_ptl_am_iface_addr_t);
    ecr_ptl_am_iface_t *ptl_iface = ecc_derived_of(iface, ecr_ptl_am_iface_t);
    ecr_ptl_am_ms_t    *ptl_ms    = ecc_derived_of(iface->ms, ecr_ptl_am_ms_t);

    ptl_addr->super.pid = ptl_ms->super.pid;
    ptl_addr->rma_pti   = ptl_ms->me.idx;
    ptl_addr->am_pti    = ptl_iface->rq.pti;

    return;
}

ECC_CLASS_DEFINE_INIT_FUNC(ecr_ptl_am_iface_t, ecr_ms_h ms,
                           ecr_device_t              *device,
                           ecr_ptl_am_iface_config_t *config)
{
    ecc_status_t       rc     = ECC_SUCCESS;
    ecr_ptl_am_ms_t   *ptl_ms = ecc_derived_of(ms, ecr_ptl_am_ms_t);
    ecc_mpool_param_t  mp_ops_param;
    ecr_ptl_md_param_t md_param;
    ecr_ptl_rq_param_t rq_param;

    rc = ECC_CLASS_CALL_SUPER_INIT(ecr_ptl_iface_t, self, ms, device,
                                   &config->super);
    if (rc != ECC_SUCCESS) {
        goto err;
    }

    /* Set capabilities. */
    self->super.super.cap = ECR_IFACE_CAP_RMA | ECR_IFACE_CAP_AM;

    /* Get MS MD for convenience. */
    self->rma_md = &ptl_ms->md;

    /* Enable progression of RMA operation. */
    ecr_ptl_iface_enable_progression(&self->super, &ptl_ms->md);

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
    rc = ecc_mpool_init(&self->rma_mp, &mp_ops_param);
    if (rc != ECC_SUCCESS)
        goto err;

    /* Initialize AM communication data structures. */
    /* Memory descriptor for local access and operation progression. */
    md_param = (ecr_ptl_md_param_t){
            .flags = PTL_CT_ACK_REQ,
    };
    rc = ecr_ptl_ms_md_init(&ptl_ms->super, &md_param, &self->am_md);
    if (rc != ECC_SUCCESS)
        goto err;

    ecr_ptl_iface_enable_progression(&self->super, &self->am_md);

    /* Work pool of operation. */
    mp_ops_param = (ecc_mpool_param_t){
            .elem_per_chunk = self->super.config.copyin_buf_per_block,
            .min_elems      = self->super.config.min_copyin_buf,
            .max_elems      = self->super.config.max_copyin_buf,
            .elem_size      = sizeof(ecr_ptl_op_t) +
                         self->super.config.eager_block_size,
            .alignment   = 64,
            .free_func   = free,
            .malloc_func = malloc,
    };
    rc = ecc_mpool_init(&self->am_mp, &mp_ops_param);
    if (rc != ECC_SUCCESS)
        goto err;

    rq_param = (ecr_ptl_rq_param_t){
            .items_per_chunk = self->super.config.num_eager_blocks,
            .min_items       = 2,
            .max_items       = self->super.config.num_eager_blocks,
            .item_size       = self->super.config.eager_block_size,
            .options         = ECR_PTL_BLOCK_AM,
            .min_free        = self->super.config.eager_block_size,
    };

    rc = ecr_ptl_rq_init(&self->super, &rq_param, &self->rq);
    if (rc != ECC_SUCCESS)
        goto err;

    self->super.super.iface_addr_size  = sizeof(ecr_ptl_am_iface_addr_t);
    self->super.super.packed_rkey_size = 0;

err:
    return rc;
}

ECC_CLASS_DEFINE_CLEAN_FUNC(ecr_ptl_am_iface_t)
{
    ecc_status_t     rc;
    ecr_ptl_am_ms_t *ptl_am_ms = ecc_derived_of(self->super.super.ms,
                                                ecr_ptl_am_ms_t);

    rc = ecr_ptl_ms_md_fini(&self->am_md);
    if (rc != ECC_SUCCESS)
        goto err;

    rc = ecr_ptl_ms_me_fini(&ptl_am_ms->super, &ptl_am_ms->me);
    if (rc != ECC_SUCCESS)
        goto err;

    ecc_mpool_fini(&self->am_mp);

    ecc_mpool_fini(&self->rma_mp);

    rc = ecr_ptl_rq_fini(&self->rq);
    if (rc != ECC_SUCCESS) {
        ECC_LOG_ERROR("PTL: could not release am receive queue.");
        goto err;
    }

    ECC_CLASS_CALL_SUPER_CLEAN(ecr_ptl_iface_t, self);
err:
    return;
}

ECC_CLASS_DEFINE(ecr_ptl_am_iface_t, ecr_ptl_iface_t);

ecc_status_t ecr_ptl_am_iface_open(ecr_ms_h ms, ecr_iface_config_t *config,
                                   ecr_iface_h *iface_p)
{
    ecc_status_t               rc = ECC_SUCCESS;
    ecr_ptl_iface_t           *ptl_iface;
    ecr_ptl_am_iface_config_t *ptl_config =
            ecc_derived_of(config, ecr_ptl_am_iface_config_t);

    rc = ECC_CLASS_NEW(ecr_ptl_am_iface_t, &ptl_iface, ms, ms->dev, ptl_config);
    if (rc != ECC_SUCCESS)
        goto err;

    ptl_iface->ops.handle_ev = ecr_ptl_am_iface_handle_ev;

    ptl_iface->super.ops.send_am_bcopy  = ecr_ptl_send_am_bcopy;
    ptl_iface->super.ops.send_am_zcopy  = ecr_ptl_send_am_zcopy;
    ptl_iface->super.ops.put_zcopy      = ecr_ptl_am_put_zcopy;
    ptl_iface->super.ops.get_zcopy      = ecr_ptl_am_get_zcopy;
    ptl_iface->super.ops.flush_iface    = ecr_ptl_am_flush_iface;
    ptl_iface->super.ops.iface_progress = ecr_ptl_iface_progress;
    ptl_iface->super.ops.iface_close    = ecr_ptl_iface_am_close;
    ptl_iface->super.ops.iface_get_addr = ecr_ptl_am_iface_get_addr;
    ptl_iface->super.ops.iface_get_attr = ecr_ptl_iface_get_attr;
    ptl_iface->super.ops.ep_create      = ecr_ptl_create_am_ep;
    ptl_iface->super.ops.ep_delete      = ecr_ptl_delete_am_ep;

    *iface_p = (ecr_iface_t *)ptl_iface;
err:
    return rc;
}

ecr_rail_t ptl_am_rail = {
        .name = "ptl_am",
        .iface_config =
                {
                        .cf      = &ecr_ptl_am_iface_config_tab,
                        .cf_size = sizeof(ecr_ptl_am_iface_config_t),
                },
        .iface_open = ecr_ptl_am_iface_open,
        .flags      = 0,
};
ECR_RAIL_REGISTER(&ptl_am_component, &ptl_am_rail);
ECC_CONFIG_REGISTER(ecr_ptl_am_iface_config_tab);
