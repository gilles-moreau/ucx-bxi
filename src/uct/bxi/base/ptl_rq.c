#include "ptl_rq.h"

#include "ptl_iface.h"

#include <stdlib.h>

static ucs_status_t uct_ptl_recv_block_init(uct_ptl_rq_t *rq,
                                            uct_ptl_recv_block_t **block_p) {
  ucs_status_t rc = UCS_OK;
  uct_ptl_recv_block_t *block;

  block = ucs_mpool_get(&rq->mp);
  if (block == NULL) {
    ucs_error("PTL: could not allocate eager block structure");
    rc = UCS_ERR_NO_MEMORY;
    goto err;
  }

  block->size = rq->config.blk_size;
  block->start = block + 1;
  block->meh = PTL_INVALID_HANDLE;
  block->rq = rq;

  ucs_debug("PTL: rq block. start=%p.", block->start);

  *block_p = block;

err:
  return rc;
}

int uct_ptl_recv_block_activate(uct_ptl_recv_block_t *block) {
  ptl_me_t me;
  ptl_match_bits_t match = 0;
  ptl_match_bits_t ign = ~0;
  uct_ptl_rq_t *rq = block->rq;
  ptl_list_t list;

  if (block->start == NULL) {
    return UCS_ERR_IO_ERROR;
  }

  me = (ptl_me_t){
      .ct_handle = PTL_CT_NONE,
      .match_bits = match,
      .ignore_bits = ign,
      .match_id =
          {
              .phys.nid = PTL_NID_ANY,
              .phys.pid = PTL_PID_ANY,
          },
      .min_free = rq->config.blk_min_free,
      .options = rq->config.blk_opts,
      .uid = PTL_UID_ANY,
      .start = block->start,
      .length = block->size,
  };

  list = rq->config.blk_opts == ECR_PTL_BLOCK_TAG ? PTL_OVERFLOW_LIST
                                                  : PTL_PRIORITY_LIST;

  return uct_ptl_wrap(PtlMEAppend(uct_ptl_iface_md(rq->iface)->nih, rq->pti,
                                  &me, list, block, &block->meh));
}

static ucs_status_t uct_ptl_recv_blocks_enable(uct_ptl_rq_t *rq) {
  ucs_status_t rc = UCS_OK;
  int i;

  ucs_list_head_init(&rq->bhead);

  for (i = 0; i < rq->config.num_blk; i++) {
    uct_ptl_recv_block_t *block = NULL;

    rc = uct_ptl_recv_block_init(rq, &block);
    if (rc != UCS_OK) {
      ucs_error("PTL: could not allocate block");
      return rc;
    }

    /* Append block to list. */
    ucs_list_add_head(&rq->bhead, &block->elem);

    /* Create the ME on the card. */
    rc = uct_ptl_recv_block_activate(block);
    if (rc != UCS_OK) {
      goto err;
    }
  }

err:
  return rc;
}

static ucs_status_t uct_ptl_recv_block_disable(ucs_list_link_t *head) {
  ucs_status_t rc = UCS_OK;
  uct_ptl_recv_block_t *block = NULL, *tmp = NULL;

  ucs_list_for_each_safe(block, tmp, head, elem) {
    ucs_mpool_put(block);

    rc = uct_ptl_wrap(PtlMEUnlink(block->meh));
    if (rc != UCS_OK)
      goto err;

    ucs_list_del(&tmp->elem);
  }
err:
  return rc;
}

static ucs_mpool_ops_t uct_ptl_rq_mpool_ops = {
    .chunk_alloc = ucs_mpool_chunk_malloc,
    .chunk_release = ucs_mpool_chunk_free,
    .obj_init = NULL,
    .obj_cleanup = NULL,
    .obj_str = NULL};

ucs_status_t uct_ptl_rq_init(uct_ptl_iface_t *iface, uct_ptl_rq_param_t *params,
                             uct_ptl_rq_t *rq) {
  ucs_status_t rc;
  ucs_mpool_params_t mp_block_params;

  rc = uct_ptl_wrap(PtlPTAlloc(uct_ptl_iface_md(iface)->nih, PTL_PT_FLOWCTRL,
                               uct_ptl_iface_md(iface)->eqh, PTL_PT_ANY,
                               &rq->pti));
  if (rc != UCS_OK) {
    goto err;
  }

  /* First, initialize memory pool of receive buffers. */
  ucs_mpool_params_reset(&mp_block_params);
  mp_block_params = (ucs_mpool_params_t){
      .max_chunk_size = params->items_per_chunk *
                        (sizeof(uct_ptl_recv_block_t) + params->item_size),
      .elems_per_chunk = params->items_per_chunk,
      .elem_size = sizeof(uct_ptl_recv_block_t) + params->item_size,
      .max_elems = params->max_items,
      .alignment = 64,
      .align_offset = 0,
      .ops = &uct_ptl_rq_mpool_ops,
      .name = "rq-blocks",
      .grow_factor = 1,
  };

  rc = ucs_mpool_init(&mp_block_params, &rq->mp);
  if (rc != UCS_OK) {
    goto err_clean_pt;
  }

  rq->config.blk_opts = params->options;
  rq->config.blk_size = params->item_size;
  rq->config.blk_min_free = params->min_free;
  rq->config.num_blk = params->items_per_chunk;
  rq->iface = iface;

  rc = uct_ptl_recv_blocks_enable(rq);

  return rc;
err_clean_pt:
  uct_ptl_wrap(PtlPTFree(uct_ptl_iface_md(iface)->nih, rq->pti));
err:
  return rc;
}

void uct_ptl_rq_fini(uct_ptl_rq_t *rq) {
  uct_ptl_recv_block_disable(&rq->bhead);

  ucs_mpool_cleanup(&rq->mp, 1);

  uct_ptl_wrap(PtlPTFree(uct_ptl_iface_md(rq->iface)->nih, rq->pti));
}
