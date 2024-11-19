#include "ptl_tag_iface.h"
#include "ptl_tag_ms.h"
#include "ptl_tag_ep.h"

#include <ecr/portals/ptl_types.h>
#include <ecr/portals/base/ptl_rq.h>

static ecc_config_entry_t ecr_ptl_tag_iface_config_entries[] = {
        {ECC_CONFIG_ELEM_ENTRY(super, "", "", ecr_ptl_tag_iface_config_t,
                               ECC_CONFIG_TYPE_TABLE(
                                       &ecr_ptl_iface_config_tab))},

        {""},
};

static ecc_config_tab_t ecr_ptl_tag_iface_config_tab = {
        "ECR_IFACE_PTL_TAG",
        ECC_LIST_INITIALIZER(NULL, NULL),
        ecr_ptl_tag_iface_config_entries,
        sizeof(ecr_ptl_tag_iface_config_t),
};

static ecc_status_t
ecr_ptl_tag_iface_handle_ev(ecr_ptl_iface_t *iface, ptl_event_t *ev)
{
    ecc_status_t          rc = ECC_SUCCESS;
    ecr_ptl_recv_block_t *block;
    unsigned              flags = 0;
    ecr_tag_context_t    *tag_ctx;
    ecr_ptl_op_t         *op;

    ECC_LOG_INFO("PORTALS: EQS EVENT '%s' eqh=%llu, idx=%d, "
                 "sz=%llu, user=%p, start=%p, "
                 "remote_offset=%llu, iface=%llu",
                 ecr_ptl_event_str[ev->type], iface->eqh, ev->pt_index,
                 ev->mlength, ev->user_ptr, ev->start, ev->remote_offset, 0);

    op = (ecr_ptl_op_t *)ev->user_ptr;
    assert(op);

    switch (ev->type) {
    case PTL_EVENT_SEARCH:
        if (ev->ni_fail_type == PTL_NI_NO_MATCH) {
            return ECC_SUCCESS;
        }
        tag_ctx         = op->tag.ctx;
        tag_ctx->tag    = (ecr_tag_t)ev->match_bits;
        tag_ctx->imm    = ev->hdr_data;
        tag_ctx->start  = NULL;
        tag_ctx->flags |= flags;

        /* call completion callback */
        op->comp->sent = ev->mlength;
        op->comp->comp_cb(op->comp);
        break;
    case PTL_EVENT_REPLY:
        assert(op->size == ev->mlength);
        op->comp->sent = ev->mlength;
        op->comp->comp_cb(op->comp);
        break;
        break;
    case PTL_EVENT_PUT_OVERFLOW:
    case PTL_EVENT_PUT:
        if (op->type == ECR_PTL_OP_BLOCK || !op->tag.ctx) {
            break;
        }
        tag_ctx             = op->tag.ctx;
        tag_ctx->tag        = (ecr_tag_t)ev->match_bits;
        tag_ctx->imm        = ev->hdr_data;
        tag_ctx->start      = ev->start;
        tag_ctx->comp.sent  = ev->mlength;
        tag_ctx->flags     |= flags;

        /* call completion callback */
        tag_ctx->comp.comp_cb(&tag_ctx->comp);
        break;
    case PTL_EVENT_GET:
        op->comp->sent = ev->mlength;
        op->comp->comp_cb(op->comp);
        break;
    case PTL_EVENT_AUTO_UNLINK:
        block = ecc_container_of(op, ecr_ptl_recv_block_t, op);
        ecr_ptl_recv_block_activate(block);
        break;
    case PTL_EVENT_AUTO_FREE:
        break;
    case PTL_EVENT_ACK:
    case PTL_EVENT_GET_OVERFLOW:
    case PTL_EVENT_ATOMIC:
    case PTL_EVENT_FETCH_ATOMIC:
    case PTL_EVENT_FETCH_ATOMIC_OVERFLOW:
    case PTL_EVENT_ATOMIC_OVERFLOW:
    case PTL_EVENT_LINK:
    case PTL_EVENT_SEND:
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

static ecc_status_t ecr_ptl_tag_flush_iface(ecr_iface_h       iface,
                                            ecr_completion_t *comp,
                                            unsigned          flags)
{
    ecc_status_t         rc;
    ptl_size_t           last_seqn;
    ecr_ptl_op_t        *op        = NULL;
    ecr_ptl_tag_iface_t *ptl_iface = ecc_derived_of(iface, ecr_ptl_tag_iface_t);

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


static void ecr_ptl_iface_tag_close(ecr_iface_h iface)
{
    ECC_CLASS_DELETE(ecr_ptl_tag_iface_t, iface);
    return;
}

static void
ecr_ptl_tag_iface_get_addr(ecr_iface_h iface, ecr_iface_addr_t *addr)
{
    ecr_ptl_tag_iface_addr_t *ptl_addr =
            ecc_derived_of(addr, ecr_ptl_tag_iface_addr_t);
    ecr_ptl_tag_iface_t *ptl_iface = ecc_derived_of(iface, ecr_ptl_tag_iface_t);
    ecr_ptl_tag_ms_t    *ptl_ms = ecc_derived_of(iface->ms, ecr_ptl_tag_ms_t);

    ptl_addr->super.pid = ptl_ms->super.pid;
    ptl_addr->rma_pti   = ptl_ms->super.pti;
    ptl_addr->tag_pti   = ptl_iface->rq.pti;

    return;
}

ECC_CLASS_DEFINE_INIT_FUNC(ecr_ptl_tag_iface_t, ecr_ms_h ms,
                           ecr_device_t               *device,
                           ecr_ptl_tag_iface_config_t *config)
{
    ecc_status_t       rc     = ECC_SUCCESS;
    ecr_ptl_tag_ms_t  *ptl_ms = ecc_derived_of(ms, ecr_ptl_tag_ms_t);
    ecc_mpool_param_t  mp_ops_param;
    ecr_ptl_md_param_t md_param;
    ecr_ptl_rq_param_t rq_param;

    rc = ECC_CLASS_CALL_SUPER_INIT(ecr_ptl_iface_t, self, ms, device,
                                   &config->super);
    if (rc != ECC_SUCCESS) {
        goto err;
    }

    /* Set capabilities. */
    self->super.super.cap = ECR_IFACE_CAP_RMA | ECR_IFACE_CAP_TAG;

    self->super.super.iface_addr_size  = sizeof(ecr_ptl_tag_iface_addr_t);
    self->super.super.packed_rkey_size = sizeof(ecr_ptl_tag_rkey_t);

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

    /* Initialize TAG communication data structures. */
    /* Memory descriptor for local access and operation progression. */
    md_param = (ecr_ptl_md_param_t){
            .flags = PTL_CT_ACK_REQ,
    };
    rc = ecr_ptl_ms_md_init(&ptl_ms->super, &md_param, &self->tag_md);
    if (rc != ECC_SUCCESS)
        goto err;

    ecr_ptl_iface_enable_progression(&self->super, &self->tag_md);

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
    rc = ecc_mpool_init(&self->tag_mp, &mp_ops_param);
    if (rc != ECC_SUCCESS)
        goto err;

    rq_param = (ecr_ptl_rq_param_t){
            .items_per_chunk = self->super.config.num_eager_blocks,
            .min_items       = 2,
            .max_items       = self->super.config.num_eager_blocks,
            .item_size       = self->super.config.eager_block_size,
            .options         = ECR_PTL_BLOCK_TAG,
            .min_free        = self->super.config.eager_block_size,
    };

    rc = ecr_ptl_rq_init(&self->super, &rq_param, &self->rq);
    if (rc != ECC_SUCCESS)
        goto err;

err:
    return rc;
}

ECC_CLASS_DEFINE_CLEAN_FUNC(ecr_ptl_tag_iface_t)
{
    ecc_status_t rc;

    rc = ecr_ptl_ms_md_fini(&self->tag_md);
    if (rc != ECC_SUCCESS)
        goto err;

    ecc_mpool_fini(&self->tag_mp);

    ecc_mpool_fini(&self->rma_mp);

    rc = ecr_ptl_rq_fini(&self->rq);
    if (rc != ECC_SUCCESS) {
        ECC_LOG_ERROR("PTL: could not release tag receive queue.");
        goto err;
    }

    ECC_CLASS_CALL_SUPER_CLEAN(ecr_ptl_iface_t, self);
err:
    return;
}

ECC_CLASS_DEFINE(ecr_ptl_tag_iface_t, ecr_ptl_iface_t);

ecc_status_t ecr_ptl_tag_iface_open(ecr_ms_h ms, ecr_iface_config_t *config,
                                    ecr_iface_h *iface_p)
{
    ecc_status_t                rc = ECC_SUCCESS;
    ecr_ptl_iface_t            *ptl_iface;
    ecr_ptl_tag_iface_config_t *ptl_config =
            ecc_derived_of(config, ecr_ptl_tag_iface_config_t);

    rc = ECC_CLASS_NEW(ecr_ptl_tag_iface_t, &ptl_iface, ms, ms->dev,
                       ptl_config);
    if (rc != ECC_SUCCESS)
        goto err;

    ptl_iface->ops.handle_ev = ecr_ptl_tag_iface_handle_ev;

    ptl_iface->super.ops.send_tag_bcopy = ecr_ptl_send_tag_bcopy;
    ptl_iface->super.ops.send_tag_zcopy = ecr_ptl_send_tag_zcopy;
    ptl_iface->super.ops.recv_tag_zcopy = ecr_ptl_recv_tag_zcopy;
    ptl_iface->super.ops.put_zcopy      = ecr_ptl_tag_put_zcopy;
    ptl_iface->super.ops.get_zcopy      = ecr_ptl_tag_get_zcopy;
    ptl_iface->super.ops.flush_iface    = ecr_ptl_tag_flush_iface;
    ptl_iface->super.ops.iface_progress = ecr_ptl_iface_progress;
    ptl_iface->super.ops.iface_close    = ecr_ptl_iface_tag_close;
    ptl_iface->super.ops.iface_get_addr = ecr_ptl_tag_iface_get_addr;
    ptl_iface->super.ops.iface_get_attr = ecr_ptl_iface_get_attr;
    ptl_iface->super.ops.ep_create      = ecr_ptl_create_tag_ep;
    ptl_iface->super.ops.ep_delete      = ecr_ptl_delete_tag_ep;

    *iface_p = (ecr_iface_t *)ptl_iface;
err:
    return rc;
}

ecr_rail_t ptl_tag_rail = {
        .name = "ptl_tag",
        .iface_config =
                {
                        .cf      = &ecr_ptl_tag_iface_config_tab,
                        .cf_size = sizeof(ecr_ptl_tag_iface_config_t),
                },
        .iface_open = ecr_ptl_tag_iface_open,
        .flags      = 0,
};
ECR_RAIL_REGISTER(&ptl_tag_component, &ptl_tag_rail);
ECC_CONFIG_REGISTER(ecr_ptl_tag_iface_config_tab);
