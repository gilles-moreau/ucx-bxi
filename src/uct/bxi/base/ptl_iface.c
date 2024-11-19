#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ptl_iface.h"

#include <ecc/type/class.h>
#include <ecc/debug/logging.h>
#include <ecc/datastruct/mpool.h>
#include <ecc/sys/math.h>

char *ecr_ptl_event_str[] = {
        [PTL_EVENT_GET]                   = "PTL_EVENT_GET",
        [PTL_EVENT_GET_OVERFLOW]          = "PTL_EVENT_GET_OVERFLOW",
        [PTL_EVENT_PUT]                   = "PTL_EVENT_PUT",
        [PTL_EVENT_PUT_OVERFLOW]          = "PTL_EVENT_PUT_OVERFLOW",
        [PTL_EVENT_ATOMIC]                = "PTL_EVENT_ATOMIC",
        [PTL_EVENT_ATOMIC_OVERFLOW]       = "PTL_EVENT_ATOMIC_OVERFLOW",
        [PTL_EVENT_FETCH_ATOMIC]          = "PTL_EVENT_FETCH_ATOMIC",
        [PTL_EVENT_FETCH_ATOMIC_OVERFLOW] = "PTL_EVENT_FETCH_ATOMIC_OVERFLOW",
        [PTL_EVENT_REPLY]                 = "PTL_EVENT_REPLY",
        [PTL_EVENT_SEND]                  = "PTL_EVENT_SEND",
        [PTL_EVENT_ACK]                   = "PTL_EVENT_ACK",
        [PTL_EVENT_PT_DISABLED]           = "PTL_EVENT_PT_DISABLED",
        [PTL_EVENT_LINK]                  = "PTL_EVENT_LINK",
        [PTL_EVENT_AUTO_UNLINK]           = "PTL_EVENT_AUTO_UNLINK",
        [PTL_EVENT_AUTO_FREE]             = "PTL_EVENT_AUTO_FREE",
        [PTL_EVENT_SEARCH]                = "PTL_EVENT_SEARCH",
};

static ecc_config_entry_t ecr_ptl_iface_config_entries[] = {
        {ECC_CONFIG_ELEM_ENTRY(super, "name=myifacenewname", "",
                               ecr_ptl_iface_config_t,
                               ECC_CONFIG_TYPE_TABLE(&ecr_iface_config_tab))},

        {ECC_CONFIG_ELEM_ENTRY(
                max_events, "2048",
                "Maximum number of events per event queue (default: 2048).",
                ecr_ptl_iface_config_t, ECC_CONFIG_TYPE_INT)},

        {ECC_CONFIG_ELEM_ENTRY(
                max_outstanding_ops, "2048",
                "Maximum number of outstanding operations (default: 2048).",
                ecr_ptl_iface_config_t, ECC_CONFIG_TYPE_INT)},

        {ECC_CONFIG_ELEM_ENTRY(
                copyin_buf_per_block, "2",
                "Number of copyin buffers allocated per block (default: 2)",
                ecr_ptl_iface_config_t, ECC_CONFIG_TYPE_INT)},

        {ECC_CONFIG_ELEM_ENTRY(min_copyin_buf, "2",
                               "Minimum number of copyin buffers per working "
                               "queues (default: 2)",
                               ecr_ptl_iface_config_t, ECC_CONFIG_TYPE_INT)},

        {ECC_CONFIG_ELEM_ENTRY(max_copyin_buf, "8",
                               "Maximum number of copyin buffers per working "
                               "queues (default: 8)",
                               ecr_ptl_iface_config_t, ECC_CONFIG_TYPE_INT)},

        {ECC_CONFIG_ELEM_ENTRY(num_eager_blocks, "32",
                               "Number of eager blocks for receiving "
                               "unexpected messages (default: 32).",
                               ecr_ptl_iface_config_t, ECC_CONFIG_TYPE_INT)},

        {ECC_CONFIG_ELEM_ENTRY(eager_block_size, "8192",
                               "Size of a single eager block (default: 8192).",
                               ecr_ptl_iface_config_t, ECC_CONFIG_TYPE_INT)},

        {""},
};

ecc_config_tab_t ecr_ptl_iface_config_tab = {
        "ECR_IFACE_PTL",
        ECC_LIST_INITIALIZER(NULL, NULL),
        ecr_ptl_iface_config_entries,
        sizeof(ecr_ptl_iface_config_t),
};

void ecr_ptl_iface_get_attr(ecr_iface_h iface, ecr_iface_attr_t *attr)
{
    ecr_ptl_iface_t *ptl_if = ecc_derived_of(iface, ecr_ptl_iface_t);

    attr->iface.cap.am.max_bcopy  = ptl_if->config.eager_block_size;
    attr->iface.cap.am.max_zcopy  = ptl_if->config.max_msg_size;
    attr->iface.cap.am.max_iovecs = ptl_if->config.max_iovecs;

    attr->iface.cap.tag.max_bcopy  = 0;
    attr->iface.cap.tag.max_zcopy  = 0;
    attr->iface.cap.tag.max_iovecs = 0;

    attr->iface.cap.rma.max_put_bcopy = 0;
    attr->iface.cap.rma.max_put_zcopy = ptl_if->config.max_msg_size;
    attr->iface.cap.rma.max_get_bcopy = 0;
    attr->iface.cap.rma.max_get_zcopy = ptl_if->config.max_msg_size;

    attr->iface.cap.ato.max_post_size  = ptl_if->config.max_atomic_size;
    attr->iface.cap.ato.max_fetch_size = ptl_if->config.max_atomic_size;

    attr->iface.cap.flags = ptl_if->super.cap;

    attr->iface.iface_addr_size = ptl_if->super.iface_addr_size;

    attr->iface.cap.flags = ptl_if->super.cap;

    attr->mem.cap.max_reg      = PTL_SIZE_MAX;
    attr->mem.size_packed_rkey = ptl_if->super.packed_rkey_size;
}

#define seqn_gt(a, b) ((int64_t)((a) - (b)) > 0)
ecc_status_t ecr_ptl_md_progress(ecr_ptl_md_t *md)
{
    ecc_status_t     rc = ECC_SUCCESS;
    ecc_queue_iter_t iter;
    ecr_ptl_op_t    *op;

    if (ecc_queue_is_empty(&md->opq)) {
        return rc;
    }

    rc = ecr_ptl_wrap(PtlCTGet(md->cth, &md->p_cnt));
    if (rc != ECC_SUCCESS) {
        goto err;
    }

    if (md->p_cnt.failure > 0) {
        rc = ECC_ERR_INTERNAL;
        goto err;
    }

    ecc_queue_for_each_safe(op, iter, ecr_ptl_op_t, &md->opq, elem) {
        if (seqn_gt(md->p_cnt.success, op->seqn)) {
            ecc_queue_del_iter(&md->opq, iter);
            if (op->comp != NULL) {
                op->comp->sent = op->size;
                op->comp->comp_cb(op->comp);
            }
            ecc_mpool_push(op);
        }
    }

err:
    return rc;
}

ecc_status_t ecr_ptl_iface_progress(ecr_iface_h super)
{
    ecc_status_t     rc;
    int              ret;
    ptl_event_t      ev;
    ecr_ptl_md_t    *md;
    ecr_ptl_iface_t *iface = ecc_derived_of(super, ecr_ptl_iface_t);

    ecc_list_for_each(md, &iface->mds, ecr_ptl_md_t, elem) {
        rc = ecr_ptl_md_progress(md);
        if (rc != ECC_SUCCESS)
            goto out;
    }

    while (1) {
        ret = PtlEQGet(iface->eqh, &ev);

        switch (ret) {
        case PTL_OK:
            rc = iface->ops.handle_ev(iface, &ev);
            if (rc != ECC_SUCCESS)
                goto out;
            break;
        case PTL_EQ_EMPTY:
            goto out;
            break;
        case PTL_EQ_DROPPED:
            goto out;
            break;
        default:
            ecr_ptl_rc_log(ret);
            rc = ECC_ERR_INTERNAL;
            goto out;
        }
    }

out:
    return rc;
}


ECC_CLASS_DEFINE_INIT_FUNC(ecr_ptl_iface_t, ecr_ms_h ms, ecr_device_t *device,
                           ecr_ptl_iface_config_t *config)
{
    ecc_status_t  rc     = ECC_SUCCESS;
    ecr_ptl_ms_t *ptl_ms = ecc_derived_of(ms, ecr_ptl_ms_t);

    rc = ECC_CLASS_CALL_SUPER_INIT(ecr_iface_t, self, ms, &config->super);
    if (rc != ECC_SUCCESS)
        goto err;

    self->config.copyin_buf_per_block = config->copyin_buf_per_block;
    self->config.min_copyin_buf       = config->min_copyin_buf;
    self->config.max_copyin_buf       = config->max_copyin_buf;
    self->config.eager_block_size     = config->eager_block_size;
    self->config.num_eager_blocks     = config->num_eager_blocks;
    self->config.max_events           = config->max_events;
    self->config.max_outstanding_ops  = config->max_outstanding_ops;

    self->config.max_iovecs   = ptl_ms->limits.max_iovecs;
    self->config.max_msg_size = ptl_ms->limits.max_msg_size;

    rc = ecr_ptl_wrap(
            PtlEQAlloc(ptl_ms->nih, self->config.max_events, &self->eqh));
    if (rc != ECC_SUCCESS) {
        goto err_super;
    }

    ecc_list_init_head(&self->mds);

    return rc;

err_super:
    ECC_CLASS_CALL_SUPER_CLEAN(ecr_iface_t, self);
err:
    return rc;
}

ECC_CLASS_DEFINE_CLEAN_FUNC(ecr_ptl_iface_t)
{
    ecr_ptl_wrap(PtlEQFree(self->eqh));

    ECC_CLASS_CALL_SUPER_CLEAN(ecr_iface_t, self);

    return;
}

ECC_CLASS_DEFINE(ecr_ptl_iface_t, ecr_iface_t);
ECC_CONFIG_REGISTER(ecr_ptl_iface_config_tab);
