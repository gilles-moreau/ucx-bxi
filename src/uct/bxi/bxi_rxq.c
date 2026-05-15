#include "bxi_rxq.h"
#include "bxi.h"
#include <ucs/profile/profile.h>

#define UCT_BXI_CT_INIT (ptl_ct_event_t){.success = 0, .failure = 0}

void uct_bxi_recv_block_deactivate(uct_bxi_recv_block_t *block)
{
  ucs_status_t status;

  if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOADED) {
    ucs_assert(!PtlHandleIsEqual(block->cth, PTL_CT_NONE));
    status = uct_bxi_wrap(PtlCTCancelTriggered(block->cth));
    if (status != UCS_OK) {
      ucs_warn("BXI: tried to cancel attached trig operation. block=%p", block);
    }
  }

  PtlMEUnlink(block->meh);
}

static UCS_F_ALWAYS_INLINE int uct_bxi_is_overflow(ptl_size_t thresh,
                                                   ptl_size_t inc)
{
  return thresh > UINT64_MAX - inc;
}

void uct_bxi_recv_block_release(uct_bxi_recv_block_t *block)
{
  ucs_status_t status;

  ucs_assert(block->flags & UCT_BXI_RECV_BLOCK_FLAG_IN_USE);

  block->meh   = PTL_INVALID_HANDLE;
  block->flags = 0;

  /* Counter value needs to be reset otherwise thresholds comparison will 
   * hit integer overflow problems. Since PtlCTSet is blocking, do it just 
   * before overflow happens.
   * */
  //TODO: add a test
  if (uct_bxi_is_overflow(block->ct_value, block->eager_limit)) {
    status = uct_bxi_wrap(PtlCTSet(block->cth, UCT_BXI_CT_INIT));
    if (status != UCS_OK) {
      ucs_fatal("BXI: could not reset counter.");
    }
    block->ct_value = 0;
  }

  ucs_mpool_put(block);
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
      ucs_error("BXI: could not allocate eager block structure.");
      rc = UCS_ERR_NO_MEMORY;
      goto err;
    }

    /* Create the ME on the card. */
    rc = uct_bxi_recv_block_unexp_activate(block);
    if (rc != UCS_OK) {
      goto err;
    }

    block->flags |= UCT_BXI_RECV_BLOCK_FLAG_IN_USE;
    ucs_list_add_head(&rxq->bhead, &block->c_elem);
  }

err:
  return rc;
}

static void uct_bxi_rxq_block_init(ucs_mpool_t *mp, void *obj, void *chunk)
{
  uct_bxi_rxq_t        *rxq   = ucs_container_of(mp, uct_bxi_rxq_t, mp);
  uct_bxi_recv_block_t *block = (uct_bxi_recv_block_t *)obj;

  block->flags   = 0;
  block->size    = rxq->config.blk_size;
  block->start   = block + 1;
  block->rxq     = rxq;
  block->list    = rxq->list;
  block->meh     = PTL_INVALID_HANDLE;
  block->cth     = PTL_CT_NONE;
  block->handler = rxq->handler;
}

static void uct_bxi_rxq_block_cleanup(ucs_mpool_t *mp, void *obj)
{
  uct_bxi_recv_block_t *block = (uct_bxi_recv_block_t *)obj;

  uct_bxi_recv_block_deactivate(block);
  //uct_bxi_recv_block_release(block);
}

static ucs_mpool_ops_t uct_bxi_rxq_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = uct_bxi_rxq_block_init,
        .obj_cleanup   = uct_bxi_rxq_block_cleanup,
        .obj_str       = NULL};

ucs_status_t uct_bxi_rxq_create(uct_bxi_rxq_param_t *params,
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

  rxq->flags           = params->flags;
  rxq->nih             = params->nih;
  rxq->eqh             = params->eqh;
  rxq->list            = params->list;
  rxq->handler         = params->handler;
  rxq->config.num_blk  = params->mp.max_bufs;
  rxq->config.blk_size = params->num_segs * params->seg_size;

  status = uct_bxi_wrap(PtlPTAlloc(params->nih, PTL_PT_FLOWCTRL, params->eqh,
                                   PTL_PT_ANY, &rxq->pti));
  if (status != UCS_OK) {
    goto err;
  }
  //NOTE: With tag-matching, pti is sent within the ptl hdr data and is
  //      restricted to 8 bits.
  ucs_assert(rxq->pti <= UINT8_MAX);

  /* No receive blocks for eager messages are requested. */
  if (params->flags & UCT_BXI_RXQ_FLAG_EMPTY_MEMPOOL) {
    goto out;
  }

#if HAVE_BXI3_R6LITE
  rxq->unexp_le.ct_handle         = PTL_CT_NONE;
  rxq->unexp_le.uid               = PTL_UID_ANY;
  rxq->unexp_le.min_free          = params->seg_size;
  rxq->unexp_le.options           = PTL_LE_OP_PUT | PTL_LE_MANAGE_LOCAL |
                          PTL_LE_EVENT_LINK_DISABLE |
                          PTL_LE_MAY_ALIGN;
#else
  rxq->unexp_me.ct_handle         = PTL_CT_NONE;
  rxq->unexp_me.match_bits        = 0;
  rxq->unexp_me.ignore_bits       = ~0;
  rxq->unexp_me.min_free          = params->seg_size;
  rxq->unexp_me.match_id.phys.nid = PTL_NID_ANY;
  rxq->unexp_me.match_id.phys.pid = PTL_PID_ANY;
  rxq->unexp_me.uid               = PTL_UID_ANY;
  rxq->unexp_me.options           = PTL_ME_OP_PUT | PTL_ME_MANAGE_LOCAL |
                          PTL_ME_NO_TRUNCATE | PTL_ME_EVENT_LINK_DISABLE |
                          PTL_ME_MAY_ALIGN;
#endif

  //FIXME: we may question the use of a memory pool here since the number of
  //       buffer is fixed and everything should be posted to the NIC at init
  //       time. To implement a dynamic behavior then block initialization
  //       should be moved to the memory pool init callback.

  /* First, initialize memory pool of receive buffers. */
  ucs_mpool_params_reset(&mp_block_params);
  mp_block_params.max_chunk_size  = params->mp.max_chunk_size;
  mp_block_params.elems_per_chunk = params->mp.bufs_grow;
  mp_block_params.elem_size =
          sizeof(uct_bxi_recv_block_t) + rxq->config.blk_size;
  mp_block_params.max_elems    = params->mp.max_bufs;
  mp_block_params.alignment    = UCS_SYS_CACHE_LINE_SIZE;
  mp_block_params.align_offset = sizeof(uct_bxi_recv_block_t);
  mp_block_params.ops          = &uct_bxi_rxq_mpool_ops;
  mp_block_params.name         = params->name;
  mp_block_params.grow_factor  = params->mp.grow_factor;

  status = ucs_mpool_init(&mp_block_params, &rxq->mp);
  if (status != UCS_OK) {
    goto err_clean_pt;
  }

  /* Then create Portals Memory Entries associated with them. */
  status = uct_bxi_rxq_recv_blocks_enable(rxq);
  if (status != UCS_OK) {
    goto err_clean_mp;
  }

out:
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
  uct_bxi_recv_block_t *block, *tmp;

  //FIXME: refacto. In order for the block to be cleaned up during
  //       mpool cleanup, element have to be put back to memory
  //       pool. uct_bxi_recv_block_release may be used both for
  //       expected block in tag matching and during mpool element
  //       cleanup which was conflicting.
  if (!(rxq->flags & UCT_BXI_RXQ_FLAG_EMPTY_MEMPOOL)) {
    ucs_list_for_each_safe (block, tmp, &rxq->bhead, c_elem) {
      ucs_list_del(&block->c_elem);
      ucs_mpool_put(block);
    }
    //NOTE: no need to check for leaks since the pool is static.
    ucs_mpool_cleanup(&rxq->mp, 0);
  }

  uct_bxi_wrap(PtlPTFree(rxq->nih, rxq->pti));

  ucs_free(rxq);
}
