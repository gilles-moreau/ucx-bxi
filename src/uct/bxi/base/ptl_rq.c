#include "ptl_rq.h"

#include "ptl_iface.h"

#include <stdlib.h>

static ecc_status_t
ecr_ptl_recv_block_init(ecr_ptl_rq_t *rq, ecr_ptl_recv_block_t **block_p)
{
    ecc_status_t          rc = ECC_SUCCESS;
    ecr_ptl_recv_block_t *block;

    block = ecc_mpool_pop(&rq->mp);
    if (block == NULL) {
        ECC_LOG_ERROR("PTL: could not allocate eager block structure");
        rc = ECC_ERR_OUT_OF_MEMORY;
        goto err;
    }

    block->size  = rq->config.blk_size;
    block->start = block + 1;
    block->meh   = PTL_INVALID_HANDLE;
    block->rq    = rq;

    *block_p = block;
err:
    return rc;
}

int ecr_ptl_recv_block_activate(ecr_ptl_recv_block_t *block)
{
    ptl_me_t         me;
    ptl_match_bits_t match = 0;
    ptl_match_bits_t ign   = ~0;
    ecr_ptl_rq_t    *rq    = block->rq;
    ptl_list_t       list;

    if (block->start == NULL) {
        return ECC_ERR_INTERNAL;
    }

    me = (ptl_me_t){
            .ct_handle   = PTL_CT_NONE,
            .match_bits  = match,
            .ignore_bits = ign,
            .match_id =
                    {
                            .phys.nid = PTL_NID_ANY,
                            .phys.pid = PTL_PID_ANY,
                    },
            .min_free = rq->config.blk_min_free,
            .options  = rq->config.blk_opts,
            .uid      = PTL_UID_ANY,
            .start    = block->start,
            .length   = block->size,
    };

    list = rq->config.blk_opts == ECR_PTL_BLOCK_TAG ? PTL_OVERFLOW_LIST :
                                                      PTL_PRIORITY_LIST;

    return ecr_ptl_wrap(PtlMEAppend(ecr_ptl_iface_ms(rq->iface)->nih, rq->pti,
                                    &me, list, block, &block->meh));
}

static ecc_status_t ecr_ptl_recv_blocks_enable(ecr_ptl_rq_t *rq)
{
    ecc_status_t rc = ECC_SUCCESS;
    int          i;

    ecc_list_init_head(&rq->bhead);

    for (i = 0; i < rq->config.num_blk; i++) {
        ecr_ptl_recv_block_t *block = NULL;

        rc = ecr_ptl_recv_block_init(rq, &block);
        if (rc != ECC_SUCCESS) {
            ECC_LOG_ERROR("PTL: could not allocate block");
            return rc;
        }

        /* Append block to list. */
        ecc_list_push_head(&rq->bhead, &block->elem);

        /* Create the ME on the card. */
        rc = ecr_ptl_recv_block_activate(block);
        if (rc != ECC_SUCCESS) {
            goto err;
        }
    }

err:
    return rc;
}

static ecc_status_t ecr_ptl_recv_block_disable(ecc_list_elem_t *head)
{
    ecc_status_t          rc    = ECC_SUCCESS;
    ecr_ptl_recv_block_t *block = NULL, *tmp = NULL;

    ecc_list_for_each_safe(block, tmp, head, ecr_ptl_recv_block_t, elem) {
        ecc_mpool_push(block);

        rc = ecr_ptl_wrap(PtlMEUnlink(block->meh));
        if (rc != ECC_SUCCESS)
            goto err;

        ecc_list_del(&tmp->elem);
    }
err:
    return rc;
}

ecc_status_t ecr_ptl_rq_init(ecr_ptl_iface_t *iface, ecr_ptl_rq_param_t *params,
                             ecr_ptl_rq_t *rq)
{
    ecc_status_t rc;

    rc = ecr_ptl_wrap(PtlPTAlloc(ecr_ptl_iface_ms(iface)->nih, PTL_PT_FLOWCTRL,
                                 iface->eqh, PTL_PT_ANY, &rq->pti));
    if (rc != ECC_SUCCESS) {
        goto err;
    }

    /* First, initialize memory pool of receive buffers. */
    ecc_mpool_param_t mp_block_params = {
            .elem_per_chunk = params->items_per_chunk,
            .elem_size      = sizeof(ecr_ptl_recv_block_t) + params->item_size,
            .min_elems      = params->min_items,
            .max_elems      = params->max_items,
            .alignment      = 64,
            .malloc_func    = malloc,
            .free_func      = free,
    };

    rc = ecc_mpool_init(&rq->mp, &mp_block_params);
    if (rc != ECC_SUCCESS) {
        goto err;
    }

    rq->config.blk_opts     = params->options;
    rq->config.blk_size     = params->items_per_chunk * params->item_size;
    rq->config.blk_min_free = params->min_free;
    rq->config.num_blk      = params->items_per_chunk;
    rq->iface               = iface;

    rc = ecr_ptl_recv_blocks_enable(rq);

err:
    return rc;
}

ecc_status_t ecr_ptl_rq_fini(ecr_ptl_rq_t *rq)
{
    ecc_status_t rc;

    rc = ecr_ptl_recv_block_disable(&rq->bhead);
    if (rc != ECC_SUCCESS)
        goto err;

    ecc_mpool_fini(&rq->mp);

    rc = ecr_ptl_wrap(PtlPTFree(ecr_ptl_iface_ms(rq->iface)->nih, rq->pti));

err:
    return rc;
}
