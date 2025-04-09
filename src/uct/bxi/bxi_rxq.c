#include "bxi_rxq.h"
#include "bxi.h"
#include "bxi_iface.h"

#include <stdlib.h>

ucs_status_t uct_bxi_recv_block_activate(uct_bxi_recv_block_t        *block,
                                         uct_bxi_recv_block_params_t *params)
{
  ptl_me_t       me;
  uct_bxi_rxq_t *rxq = block->rxq;

  switch (block->list) {
  case PTL_PRIORITY_LIST:
    me = (ptl_me_t){
            .ct_handle   = params->cth,
            .match_bits  = params->match,
            .ignore_bits = params->ign,
            .match_id    = {.phys.nid = PTL_NID_ANY, .phys.pid = PTL_PID_ANY},
            .options     = params->options,
            .uid         = PTL_UID_ANY,
            .start       = params->start,
            .length      = params->size};
    break;
  case PTL_OVERFLOW_LIST:
    me = (ptl_me_t){
            .ct_handle   = PTL_CT_NONE,
            .match_bits  = 0,
            .ignore_bits = ~0,
            .match_id    = {.phys.nid = PTL_NID_ANY, .phys.pid = PTL_PID_ANY},
            .options     = PTL_ME_OP_PUT | PTL_ME_MANAGE_LOCAL |
                       PTL_ME_EVENT_LINK_DISABLE | PTL_ME_MAY_ALIGN |
                       PTL_ME_IS_ACCESSIBLE,
            .uid    = PTL_UID_ANY,
            .start  = block->start,
            .length = block->size};
    break;
  default:
    ucs_fatal("BXI: block list unknown.");
    break;
  }

  if (block->start == NULL) {
    return UCS_ERR_IO_ERROR;
  }

  return uct_bxi_wrap(PtlMEAppend(rxq->nih, rxq->pti, &me, block->list, block,
                                  &block->meh));
}

void uct_bxi_recv_block_deactivate(uct_bxi_recv_block_t *block)
{
  int ret;

  ret = PtlMEUnlink(block->meh);
  if (ret != PTL_OK) {
    ucs_warn("PTL: block not unlinked. pti=%d, start=%p", block->rxq->pti,
             block->start);
  }
}

static ucs_status_t uct_bxi_rxq_recv_blocks_enable(uct_bxi_rxq_t *rxq)
{
  ucs_status_t rc = UCS_OK;
  int          i;

  ucs_list_head_init(&rxq->bhead);

  for (i = 0; i < rxq->config.num_blk; i++) {
    uct_bxi_recv_block_t *block = NULL;

    block = ucs_mpool_get(&rxq->mp);
    if (block == NULL) {
      ucs_error("PTL: could not allocate eager block structure");
      rc = UCS_ERR_NO_MEMORY;
      goto err;
    }

    /* Append block to list. */
    ucs_list_add_head(&rxq->bhead, &block->elem);

    /* Create the ME on the card. */
    rc = uct_bxi_recv_block_activate(block, NULL);
    if (rc != UCS_OK) {
      goto err;
    }
  }

err:
  return rc;
}

static ucs_status_t uct_bxi_rxq_recv_blocks_disable(uct_bxi_rxq_t *rxq)
{
  int                   ret;
  ucs_status_t          rc    = UCS_OK;
  uct_bxi_recv_block_t *block = NULL, *tmp = NULL;

  ucs_list_for_each_safe (block, tmp, &rxq->bhead, elem) {
    ret = PtlMEUnlink(block->meh);
    if (ret != PTL_OK) {
      ucs_warn("PTL: block not unlinked. pti=%d, start=%p", rxq->pti,
               block->start);
    }

    ucs_mpool_put(block);
    ucs_list_del(&tmp->elem);
  }
err:
  return rc;
}

void uct_bxi_rxq_block_init(ucs_mpool_t *mp, void *obj, void *chunk)
{
  uct_bxi_rxq_t        *rxq   = ucs_container_of(mp, uct_bxi_rxq_t, mp);
  uct_bxi_recv_block_t *block = (uct_bxi_recv_block_t *)obj;

  block->size  = rxq->config.blk_size;
  block->start = block + 1;
  block->rxq   = rxq;
  block->meh   = PTL_INVALID_HANDLE;
  block->list  = PTL_OVERFLOW_LIST;
}

static ucs_mpool_ops_t uct_bxi_rxq_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = uct_bxi_rxq_block_init,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

ucs_status_t uct_bxi_rxq_create(uct_bxi_iface_t     *iface,
                                uct_bxi_rxq_param_t *params,
                                uct_bxi_rxq_t      **rxq_p)
{
  ucs_status_t       status;
  uct_bxi_rxq_t     *rxq;
  ucs_mpool_params_t mp_block_params;

  rxq = ucs_malloc(sizeof(uct_bxi_rxq_t), "bxi-rxq");
  if (rxq == NULL) {
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }

  rxq->nih                 = params->nih;
  rxq->eqh                 = params->eqh;
  rxq->list                = params->list;
  rxq->config.blk_min_free = params->min_free;
  rxq->config.num_blk      = params->mp.max_bufs;

  status = uct_bxi_wrap(PtlPTAlloc(params->nih, PTL_PT_FLOWCTRL, params->eqh,
                                   PTL_PT_ANY, &rxq->pti));
  if (status != UCS_OK) {
    goto err;
  }

  //FIXME: we may question the use of a memory pool here since the number of
  //       buffer is fixed and everything should be posted to the NIC at init
  //       time. In implement a dynamic behavior then block initialization
  //       should be moved to the memory bool init callback.

  /* First, initialize memory pool of receive buffers. */
  ucs_mpool_params_reset(&mp_block_params);
  mp_block_params = (ucs_mpool_params_t){
          .max_chunk_size  = params->mp.max_chunk_size,
          .elems_per_chunk = params->mp.bufs_grow,
          .elem_size   = sizeof(uct_bxi_recv_block_t) + iface->config.seg_size,
          .max_elems   = params->mp.max_bufs,
          .alignment   = UCS_SYS_CACHE_LINE_SIZE,
          .ops         = &uct_bxi_rxq_mpool_ops,
          .name        = params->name,
          .grow_factor = params->mp.grow_factor,
  };
  status = ucs_mpool_init(&mp_block_params, &rxq->mp);
  if (status != UCS_OK) {
    goto err_clean_pt;
  }

  /* Then create Portals Memory Entries associated with them. */
  status = uct_bxi_rxq_recv_blocks_enable(rxq);
  if (status != UCS_OK) {
    goto err_clean_mp;
  }

  *rxq_p = rxq;

  return status;
err_clean_mp:
  ucs_mpool_cleanup(&rxq->mp, 1);
err_clean_pt:
  uct_bxi_wrap(PtlPTFree(params->nih, rxq->pti));
err_free_rxq:
  ucs_free(rxq);
err:
  return status;
}

void uct_bxi_rxq_fini(uct_bxi_rxq_t *rxq)
{
  uct_bxi_rxq_recv_blocks_disable(rxq);

  ucs_mpool_cleanup(&rxq->mp, 1);

  uct_bxi_wrap(PtlPTFree(rxq->nih, rxq->pti));

  ucs_free(rxq);
}
