#include "ptl_tag_ep.h"
#include "ptl_tag_ms.h"
#include "ptl_tag_iface.h"

#include <assert.h>

ssize_t ecr_ptl_send_tag_bcopy(ecr_ep_h ep, ecr_tag_t tag, uint64_t imm,
                               ecr_pack_callback_t pack, void *arg,
                               unsigned flags)
{
    ecc_status_t      rc     = ECC_SUCCESS;
    ecr_ptl_tag_ep_t *ptl_ep = ecc_derived_of(ep, ecr_ptl_tag_ep_t);

    void         *start = NULL;
    ssize_t       size  = 0;
    ecr_ptl_op_t *op    = ecc_mpool_pop(ptl_ep->tag_mp);

    if (op == NULL) {
        ECC_LOG_WARNING("PTL: reached max outstanding operations.");
        rc = ECC_ERR_NORESOURCES;
        goto err;
    }
    op->comp = NULL;
    op->seqn = ptl_ep->tag_md->seqn++;

    start = (void *)(op + 1);
    if (start == NULL) {
        ECC_LOG_ERROR("PTL: could not allocate bcopy buffer.");
        size = ECC_ERR_NORESOURCES;
        goto err;
    }
    size = pack(start, arg);
    if (size < 0) {
        goto err;
    }

    rc = ecr_ptl_wrap(PtlPut(ptl_ep->tag_md->mdh, (ptl_size_t)start, size,
                             PTL_CT_ACK_REQ, ptl_ep->super.pid, ptl_ep->tag_pti,
                             tag, 0, NULL, (ptl_hdr_data_t)imm));

    if (rc != ECC_SUCCESS) {
        ecc_mpool_push(op);
        size = ECC_ERR_INTERNAL;
        goto err;
    }

    ecc_queue_push(&ptl_ep->tag_md->opq, &op->elem);

err:
    return size;
}

ecc_status_t ecr_ptl_send_tag_zcopy(ecr_ep_h ep, ecr_tag_t tag, uint64_t imm,
                                    const struct iovec *iov, size_t iovcnt,
                                    unsigned flags, ecr_completion_t *ctx)
{
    return ECC_ERR_UNSUPPORTED;
#if 0 
    int                 i;
    ecc_status_t        rc       = ECC_SUCCESS;
    ecr_ptl_am_ep_t    *ptl_ep   = ecc_derived_of(ep, ecr_ptl_am_ep_t);
    ecr_ptl_am_iface_t *am_iface = ecc_derived_of(&ptl_ep->super.super.iface,
                                                  ecr_ptl_am_iface_t);
    ptl_md_t            iov_md;


    ecr_ptl_op_t *op = ecr_ptl_wq_get_item(am_iface->buf_wq);
    if (op == NULL) {
        ECC_LOG_ERROR("PTL: could not allocate operation.");
        rc = ECC_ERR_NORESOURCES;
        goto err;
    }

    op->iov.iov = malloc((iovcnt + 1) * sizeof(ptl_iovec_t));
    if (op->iov.iov == NULL) {
        ECC_LOG_ERROR("PTL: could not allocate ptl iov.");
        rc = ECC_ERR_OUT_OF_MEMORY;
        goto err;
    }

    assert(iovcnt + 1 <= (size_t)am_iface->super.super.config.max_iovec);

    /* Fill up IOV structure and compute total size. */
    op->iov.iov[0].iov_len  = header_length;
    op->iov.iov[0].iov_base = (void *)header;

    for (i = 0; i < (int)iovcnt; i++) {
        op->iov.iov[1 + i].iov_base = iov[i].iov_base;
    }

    iov_md = (ptl_md_t){
            .start     = op->iov.iov,
            .length    = iovcnt + 1,
            .ct_handle = am_iface->rma_cq->cth,
            .eq_handle = PTL_EQ_NONE,
            .options   = PTL_MD_EVENT_SEND_DISABLE | PTL_IOVEC,
    };

    /* Set Memory Descriptor handle. */
    rc = ecr_ptl_wrap(PtlMDBind(am_iface->super.nih, &iov_md, NULL));
    if (rc != ECC_SUCCESS) {
        goto err;
    }

err:
    return rc;
#endif
}

ecc_status_t ecr_ptl_recv_tag_zcopy(ecr_iface_h iface, ecr_tag_t tag,
                                    ecr_tag_t ign_tag, const struct iovec *iov,
                                    size_t iovcnt, unsigned flags,
                                    ecr_tag_context_t *ctx)
{
    ecc_status_t         rc = ECC_SUCCESS;
    ptl_me_t             me;
    unsigned int         search    = flags & ECR_IFACE_TM_SEARCH;
    ecr_ptl_tag_iface_t *ptl_iface = ecc_derived_of(iface, ecr_ptl_tag_iface_t);
    ecr_ptl_tag_ms_t    *ptl_ms = ecc_derived_of(iface->ms, ecr_ptl_tag_ms_t);

    assert(iov && iovcnt == 1);

    /* complete the ME data, this ME will be appended to the PRIORITY_LIST */
    me = (ptl_me_t){
            .ct_handle   = PTL_CT_NONE,
            .ignore_bits = ign_tag,
            .match_bits  = tag,
            .match_id    = {.phys.nid = PTL_NID_ANY, .phys.pid = PTL_PID_ANY},
            .min_free    = 0,
            .length      = iov[iovcnt - 1].iov_len,
            .start       = iov[iovcnt - 1].iov_base,
            .uid         = PTL_UID_ANY,
            .options     = PTL_ME_OP_PUT | PTL_ME_USE_ONCE |
                       PTL_ME_EVENT_LINK_DISABLE | PTL_ME_EVENT_UNLINK_DISABLE,
    };

    ecr_ptl_op_t *op = ecc_mpool_pop(&ptl_iface->tag_mp);
    if (op == NULL) {
        ECC_LOG_ERROR("PTL: maximum outstanding operations.");
        rc = ECC_ERR_NORESOURCES;
        goto err;
    }
    op->type    = ECR_PTL_OP_RECV;
    op->tag.ctx = ctx;

    if (search) {
        rc = ecr_ptl_wrap(PtlMESearch(ptl_ms->super.nih, ptl_iface->rq.pti, &me,
                                      PTL_SEARCH_ONLY, op));
    } else {
        rc = ecr_ptl_wrap(PtlMEAppend(ptl_ms->super.nih, ptl_iface->rq.pti, &me,
                                      PTL_PRIORITY_LIST, op, &op->tag.meh));
    }

err:
    return rc;
}

ecc_status_t ecr_ptl_tag_put_zcopy(ecr_ep_h ep, uint64_t local_addr,
                                   uint64_t remote_addr, ecr_mr_h mr,
                                   ecr_rkey_h rkey, size_t size,
                                   ecr_completion_t *comp)
{
    ecc_status_t        rc            = ECC_SUCCESS;
    ecr_ptl_tag_ep_t   *ptl_ep        = ecc_derived_of(ep, ecr_ptl_tag_ep_t);
    ecr_ptl_op_t       *op            = ecc_mpool_pop(ptl_ep->rma_mp);
    ecr_ptl_tag_rkey_t *ptl_rkey      = (ecr_ptl_tag_rkey_t *)rkey;
    uint64_t            remote_offset = remote_addr - ptl_rkey->offset;

    if (op == NULL) {
        ECC_LOG_WARNING("PTL: reached max outstanding operations.");
        rc = ECC_ERR_NORESOURCES;
        goto err;
    }
    op->comp = comp;
    op->size = size;
    op->seqn = ptl_ep->rma_md->seqn++;

    rc = ecr_ptl_wrap(PtlPut(ptl_ep->rma_md->mdh, (ptl_size_t)local_addr, size,
                             PTL_CT_ACK_REQ, ptl_ep->super.pid, ptl_ep->rma_pti,
                             ptl_rkey->match, remote_offset, NULL, 0));

    if (rc != ECC_SUCCESS) {
        ecc_mpool_push(op);
        size = ECC_ERR_INTERNAL;
        goto err;
    }

    ecc_queue_push(&ptl_ep->rma_md->opq, &op->elem);

err:
    return rc;
}

ecc_status_t ecr_ptl_tag_get_zcopy(ecr_ep_h ep, uint64_t local_addr,
                                   uint64_t remote_addr, ecr_mr_h mr,
                                   ecr_rkey_h rkey, size_t size,
                                   ecr_completion_t *comp)
{
    ecc_status_t        rc            = ECC_SUCCESS;
    ecr_ptl_tag_ep_t   *ptl_ep        = ecc_derived_of(ep, ecr_ptl_tag_ep_t);
    ecr_ptl_tag_rkey_t *ptl_rkey      = (ecr_ptl_tag_rkey_t *)rkey;
    ecr_ptl_op_t       *op            = ecc_mpool_pop(ptl_ep->rma_mp);
    uint64_t            remote_offset = remote_addr - ptl_rkey->offset;

    if (op == NULL) {
        ECC_LOG_WARNING("PTL: reached max outstanding operations.");
        rc = ECC_ERR_NORESOURCES;
        goto err;
    }

    op->comp = comp;
    op->size = size;
    op->seqn = ptl_ep->rma_md->seqn++;

    rc = ecr_ptl_wrap(PtlGet(ptl_ep->rma_md->mdh, (ptl_size_t)local_addr, size,
                             ptl_ep->super.pid, ptl_ep->rma_pti,
                             ptl_rkey->match, remote_offset, NULL));

    if (rc != ECC_SUCCESS) {
        ecc_mpool_push(op);
        size = ECC_ERR_INTERNAL;
        goto err;
    }

    ecc_queue_push(&ptl_ep->rma_md->opq, &op->elem);

err:
    return rc;
}


ECC_CLASS_DEFINE_INIT_FUNC(ecr_ptl_tag_ep_t, ecr_iface_h iface,
                           ecr_iface_addr_t *addr, unsigned flags)
{
    ecr_ptl_tag_iface_t *ptl_iface = ecc_derived_of(iface, ecr_ptl_tag_iface_t);
    ecr_ptl_tag_iface_addr_t *ptl_addr =
            ecc_derived_of(addr, ecr_ptl_tag_iface_addr_t);

    ECC_CLASS_CALL_SUPER_INIT(ecr_ptl_ep_t, self, iface, addr, flags);

    self->tag_mp = &ptl_iface->tag_mp;
    self->rma_mp = &ptl_iface->rma_mp;
    self->tag_md = &ptl_iface->tag_md;
    self->rma_md = ptl_iface->rma_md;

    self->tag_pti = ptl_addr->tag_pti;
    self->rma_pti = ptl_addr->rma_pti;

    return ECC_SUCCESS;
}

ECC_CLASS_DEFINE_CLEAN_FUNC(ecr_ptl_tag_ep_t)
{
    ECC_CLASS_CALL_SUPER_CLEAN(ecr_ptl_ep_t, self);
    return;
}

ECC_CLASS_DEFINE(ecr_ptl_tag_ep_t, ecr_ptl_ep_t);

ecc_status_t ecr_ptl_create_tag_ep(ecr_iface_h iface, ecr_iface_addr_t *addr,
                                   unsigned flags, ecr_ep_h *ep_p)
{
    ecc_status_t      rc;
    ecr_ptl_tag_ep_t *ep;

    rc = ECC_CLASS_NEW(ecr_ptl_tag_ep_t, &ep, iface, addr, flags);
    if (rc != ECC_SUCCESS)
        goto err;

    *ep_p = (ecr_ep_h)ep;

err:
    return rc;
}

ecc_status_t ecr_ptl_delete_tag_ep(ecr_ep_h ep)
{
    ECC_CLASS_DELETE(ecr_ptl_tag_ep_t, ep);

    return ECC_SUCCESS;
}
