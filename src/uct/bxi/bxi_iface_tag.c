#include "bxi_iface.h"

#include "bxi_ep.h"

// Block handlers
static ptl_me_t consume_me = {
        .ct_handle         = PTL_CT_NONE,
        .ignore_bits       = 0,
        .min_free          = 0,
        .length            = 0,
        .match_id.phys.nid = PTL_NID_ANY,
        .match_id.phys.pid = PTL_PID_ANY,
        .start             = NULL,
        .uid               = PTL_UID_ANY,
        .options = PTL_ME_OP_PUT | PTL_ME_USE_ONCE | PTL_ME_EVENT_COMM_DISABLE |
                   PTL_ME_EVENT_OVER_DISABLE | PTL_ME_EVENT_LINK_DISABLE |
                   PTL_ME_EVENT_FLOWCTRL_DISABLE | PTL_ME_EVENT_UNLINK_DISABLE,
};

static UCS_F_ALWAYS_INLINE void
uct_bxi_iface_consume_unexp_hdr(uct_bxi_iface_t *iface, uct_tag_t tag,
                                ptl_process_t pid)
{
  ucs_status_t    status;
  ptl_handle_me_t dummy;
  consume_me.match_bits        = tag;
  consume_me.match_id.phys.nid = pid.phys.nid;
  consume_me.match_id.phys.pid = pid.phys.pid;

  status = uct_bxi_wrap(PtlMEAppend(uct_bxi_iface_md(iface)->nih,
                                    iface->rx.tag.q->pti, &consume_me,
                                    PTL_PRIORITY_LIST, NULL, &dummy));
  if (status != UCS_OK) {
    ucs_fatal("BXI: could not consume unexpected ME");
  }
}

static ucs_status_t uct_bxi_iface_block_handle_tag_unexp(
        uct_bxi_iface_t *iface, uct_bxi_recv_block_t *block, ptl_event_t *ev)
{
  ucs_status_t        status;
  uct_bxi_hdr_rndv_t *hdr;
  size_t              length;
  uct_bxi_rndv_cnt_t *cnt = NULL;
  uct_bxi_conn_id_t   cid;
  char                packed_rkey[UCT_BXI_MD_PACKED_RKEY_SIZE];

  /* There must always have space in overflow list. */
  ucs_assert(ev->rlength == ev->mlength);

  /* Cache unexpected event for treatment in case of cancel. */
  iface->tm.unexp_ev = ev;

  if (uct_bxi_iface_is_rndv_hw(iface, ev)) {

    hdr          = UCS_PTR_BYTE_OFFSET(ev->start, iface->tm.rndv_hdr_offset);
    length       = UCT_BXI_RNDV_LENGTH_GET(ev->hdr_data);
    cid.pti      = UCT_BXI_RNDV_PTI_GET(ev->hdr_data);
    cid.conn_key = UCT_BXI_RNDV_CONN_KEY_GET(ev->hdr_data);
    cid.pid      = ev->initiator;

    /* Copy remote key so it can be used by UCP to complete the rendez-vous. 
     * It is needed to resolved remote address mapped with gdrcopy, see 
     * uct_bxi_resolve_raddr. */
    memcpy(packed_rkey, hdr->rkey, UCT_BXI_MD_PACKED_RKEY_SIZE);

    /* Increment receive counter for this PID. Since we dont know yet if 
     * the receive will be posted ever, we need to increment it. */
    status = uct_bxi_iface_get_rndv_cnt(iface, cid, &cnt);
    if (status != UCS_OK) {
      goto out;
    }
    uct_bxi_rndv_inc_recv_cnt(iface, cnt);

    status =
            iface->tm.rndv_unexp.cb(iface->tm.rndv_unexp.arg, 0, ev->match_bits,
                                    (const void *)(hdr + 1), hdr->header_length,
                                    hdr->remote_addr, length, packed_rkey);
  } else if (uct_bxi_iface_is_rndv_sw(ev->hdr_data)) {
    status = iface->tm.rndv_unexp.cb(iface->tm.rndv_unexp.arg, 0,
                                     ev->match_bits, (const void *)ev->start,
                                     ev->mlength, 0, 0, NULL);
  } else {
    status = iface->tm.eager_unexp.cb(iface->tm.eager_unexp.arg, ev->start,
                                      ev->mlength, UCT_CB_PARAM_FLAG_FIRST,
                                      ev->match_bits, ev->hdr_data, NULL);
  }

  if (status != UCS_OK) {
    goto out;
  }

  if (iface->tm.unexp_ev != NULL) {
    /* It means receive has not been posted. Otherwise, recv_cancel   
     * would have been called and event set to NULL, and the 
     * Portals4 unexpected header consumed. Its removal is needed 
     * otherwise, the next posted receive will match in the overflow 
     * list. */
    uct_bxi_iface_consume_unexp_hdr(iface, ev->match_bits, ev->initiator);
  }

out:
  return status;
}

ucs_status_t uct_bxi_iface_block_handle_tag_exp(uct_bxi_iface_t      *iface,
                                                uct_bxi_recv_block_t *block,
                                                ptl_event_t          *ev)
{
  ucs_status_t        status = UCS_OK;
  uct_bxi_conn_id_t   cid;
  uct_bxi_rndv_cnt_t *cnt = NULL;
  ptl_match_bits_t    tag;

  /* Receive block has been consumed, notify UCP layer so it can remove 
   * the tag from its expected queues. Buffer may also be removed from 
   * hash table. */
  block->ctx->tag_consumed_cb(block->ctx);
  uct_bxi_iface_tag_del_from_hash(iface, block->start);

  if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_COUNTER_ENABLED) {
    uct_bxi_recv_block_update_cnt(block, ev->mlength);
  }

  /* Now, perform protocol specific actions. */
  if (uct_bxi_iface_is_rndv_hw(iface, ev)) {

    /* Save stag and send size for rndv completion, see 
     * uct_bxi_recv_rndv_tag_handler. */
    block->send_size = UCT_BXI_RNDV_LENGTH_GET(ev->hdr_data);
    block->stag      = ev->match_bits;

    /* If rndv was not offloaded, then it must be handled in sw. */
    //NOTE: It has been kept to preserve compatibility with UCX testsuite.
    if (!(block->flags & UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOADED)) {
      /* Rendezvous was not offloaded during receive call, thus rndv recv 
       * counter not incremented, increment it now. */

      /* Build rndv counter key and get the rndv counter. */
      cid.pti      = UCT_BXI_RNDV_PTI_GET(ev->hdr_data);
      cid.conn_key = UCT_BXI_RNDV_CONN_KEY_GET(ev->hdr_data);
      cid.pid      = ev->initiator;

      status = uct_bxi_iface_get_rndv_cnt(iface, cid, &cnt);
      if (status != UCS_OK) {
        return status;
      }

      UCT_BXI_RNDV_TAG_SET(tag, cid.pti, cid.conn_key, cnt->recv);

      uct_bxi_iface_complete_rndv(iface, block, ev->hdr_data, tag,
                                  ev->initiator, block->send_size);

      uct_bxi_rndv_inc_recv_cnt(iface, cnt);
    }

    /* Call operation completion to decrement comp counter, release the 
     * block and complete recv in case REPLY event has been processed. */
    uct_bxi_iface_completion_op(block->op);
  } else {

    if (uct_bxi_iface_is_rndv_sw(ev->hdr_data)) {
      /* UCP will proceed with a normal software rendez-vous protocol. UCP 
       * requires original address, in case of GPU memory it differs from 
       * ev->start since we use the mapped by gdrcopy. */
      block->ctx->rndv_cb(block->ctx, ev->match_bits, block->orig, ev->mlength,
                          UCS_OK, 0);

    } else {
      status = ev->mlength < ev->rlength ? UCS_ERR_MESSAGE_TRUNCATED : UCS_OK;
      /* Eager expected message completion. */
      block->ctx->completed_cb(block->ctx, ev->match_bits, ev->hdr_data,
                               ev->mlength, NULL, status);
    }

    /* In case of offloaded rendez-vous, a GET operation has been 
       * attached. Remove all triggered operations attached to this ME. */
    if (block->flags & UCT_BXI_RECV_BLOCK_FLAG_RNDV_OFFLOADED) {
      ucs_assert(block->op->ep != NULL);
      uct_bxi_recv_block_cancel_triggered(block);
      uct_bxi_rndv_dec_recv_cnt(iface, block->op->ep->cnt);
    }

    /* Operation will not be used, it may be released. */
    uct_bxi_iface_release_op(block->op);

    uct_bxi_recv_block_release(block);
  }

  return UCS_OK;
}

// Init and fini
static void uct_bxi_iface_recv_block_init(ucs_mpool_t *mp, void *obj,
                                          void *chunk)
{
  uct_bxi_iface_t *iface =
          ucs_container_of(mp, uct_bxi_iface_t, tm.recv_block_mp);
  ucs_status_t          status;
  uct_bxi_recv_block_t *block = obj;
  ptl_md_t              md;

  block->flags = 0;
  block->size  = 0;
  block->start = NULL;
  block->rxq   = iface->rx.tag.q;
  block->list  = PTL_PRIORITY_LIST;
  block->meh   = PTL_INVALID_HANDLE;

  block->eager_limit = iface->config.tm.eager_limit;

  /* Initialize the byte counter for rendez-vous offload or scheduling. */
  block->ct_value = 0;
  status = uct_bxi_wrap(PtlCTAlloc(uct_bxi_iface_md(iface)->nih, &block->cth));
  if (status != UCS_OK) {
    ucs_fatal("BXI: could not allocate counter.");
  }

  /* Initialize the MD for rendez-vous offload. */
  md.eq_handle = iface->tx.eqh;
  md.length    = PTL_SIZE_MAX;
  //NOTE: We do not count bytes because we do not know in advance the
  //      actual size that will be read by the GET operation.
  md.options   = PTL_MD_EVENT_CT_REPLY | PTL_MD_EVENT_SEND_DISABLE;
  md.start     = 0;
  md.ct_handle = block->cth;

  status = uct_bxi_wrap(
          PtlMDBind(uct_bxi_iface_md(iface)->nih, &md, &block->mdh));
  if (status != UCS_OK) {
    ucs_fatal("BXI: could not bind MD.");
  }
}

static void uct_bxi_iface_recv_block_cleanup(ucs_mpool_t *mp, void *obj)
{
  uct_bxi_recv_block_t *block = obj;
  ptl_ct_event_t        ct_value;

  uct_bxi_wrap(PtlCTGet(block->cth, &ct_value));
  if (ct_value.success != block->ct_value) {
    ucs_error("BXI: error tracking ct value. exp=%lu, val=%lu",
              ct_value.success, block->ct_value);
  }

  ucs_assert(!PtlHandleIsEqual(block->cth, PTL_INVALID_HANDLE));
  uct_bxi_wrap(PtlCTFree(block->cth));

  ucs_assert(!PtlHandleIsEqual(block->cth, PTL_INVALID_HANDLE));
  uct_bxi_wrap(PtlMDRelease(block->mdh));
}

static ucs_mpool_ops_t uct_bxi_recv_block_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = uct_bxi_iface_recv_block_init,
        .obj_cleanup   = uct_bxi_iface_recv_block_cleanup,
        .obj_str       = NULL};

static void uct_bxi_iface_gop_init(ucs_mpool_t *mp, void *obj, void *chunk)
{
  ucs_status_t     status;
  uct_bxi_iface_t *iface = ucs_container_of(mp, uct_bxi_iface_t, tm.gop_mp);
  uct_bxi_gop_t   *gop   = obj;

  gop->ct_value = 0;
  gop->block    = NULL;

  status = uct_bxi_wrap(PtlCTAlloc(uct_bxi_iface_md(iface)->nih, &gop->cth));
  if (status != UCS_OK) {
    ucs_error("BXI: could not allocate counter.");
  }
}

static void uct_bxi_iface_gop_cleanup(ucs_mpool_t *mp, void *obj)
{
  uct_bxi_gop_t *gop = obj;

  ucs_assert(!PtlHandleIsEqual(gop->cth, PTL_INVALID_HANDLE));

  uct_bxi_wrap(PtlCTFree(gop->cth));
}

static ucs_mpool_ops_t uct_bxi_gop_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = uct_bxi_iface_gop_init,
        .obj_cleanup   = uct_bxi_iface_gop_cleanup,
        .obj_str       = NULL};

ucs_status_t uct_bxi_iface_tag_init(uct_bxi_iface_t              *iface,
                                    const uct_iface_params_t     *params,
                                    const uct_bxi_iface_config_t *config)
{
  ucs_status_t        status = UCS_OK;
  ucs_mpool_params_t  mp_param;
  uct_bxi_rxq_param_t rxq_param;

  if (!config->tm.enable) {
    /* HW tag matching data structure should not be initialized. */
    iface->tm.enabled = 0;
    goto err;
  }
  iface->tm.enabled = 1;

  /* First, initialize interface configuration. */
  iface->config.tm.max_tags  = config->tm.list_size;
  iface->config.tm.max_gop   = config->tm.max_gop;
  iface->config.tm.max_zcopy = config->seg_size;
  iface->config.tm.max_hdr   = UCT_BXI_RNDV_MAX_HDR_LENGTH;
  //FIXME: reset to make payload up to 8192
  iface->config.tm.eager_limit = config->seg_size;

  iface->config.rx.tag_mp = config->rx.tag_mp;
  //FIXME: Memory pool max elements is reset here, thus overwriting initial
  //       configuration. See FIXME comment in rxq_create about Memory Pool
  //       usage.
  iface->config.rx.tag_mp.max_bufs = config->rx.max_queue_len;

  iface->tm.eager_unexp.cb = params->eager_cb;
  iface->tm.rndv_unexp.cb  = params->rndv_cb;
  iface->tm.eager_unexp.arg =
          UCT_IFACE_PARAM_VALUE(params, eager_arg, HW_TM_EAGER_ARG, NULL);
  iface->tm.rndv_unexp.arg =
          UCT_IFACE_PARAM_VALUE(params, rndv_arg, HW_TM_RNDV_ARG, NULL);
  iface->tm.unexp_ev = NULL;

  /*
   * For hardware rendezvous, payload is located before the header so that 
   * is may fit directly in the user buffer in case of match. If message 
   * is received in the overflow list instead, the "eager" part of the 
   * payload will be copied on PTL_EVENT_PUT_OVERFLOW.
   *
   * +-+ pointer to ev->start in block handlers 
   * |
   * |          + uct_bxi_hdr_rndv_t
   * |          |                    
   * |          |                    + user hdr
   * |          |                    |
   * v          v                    v
   * +-----------------------------------------+
   * | payload  | uct_bxi_hdr_rndv_t |         |
   * |          |                    |         |
   * +-----------------------------------------+
   */
  iface->tm.rndv_hdr_offset =
          iface->config.tm.eager_limit -
          (sizeof(uct_bxi_hdr_rndv_t) + iface->config.tm.max_hdr);

  kh_init_inplace(uct_bxi_tag_addrs, &iface->tm.tag_addrs);

  /* Connection map used to handle rndv counters. */
  kh_init_inplace(uct_bxi_conn_map, &iface->tm.conn_map);

  rxq_param.flags    = 0;
  rxq_param.eqh      = iface->rx.eqh;
  rxq_param.nih      = uct_bxi_iface_md(iface)->nih;
  rxq_param.mp       = iface->config.rx.tag_mp;
  rxq_param.num_segs = iface->config.rx.num_seg;
  rxq_param.seg_size = iface->config.seg_size;
  rxq_param.list     = PTL_OVERFLOW_LIST;
  rxq_param.name     = "rxq-tag";
  rxq_param.handler  = uct_bxi_iface_block_handle_tag_unexp;

  status = uct_bxi_rxq_create(&rxq_param, &iface->rx.tag.q);
  if (status != UCS_OK) {
    goto err;
  }

  /* Pool of receive blocks for receiving expected messages. */
  ucs_mpool_params_reset(&mp_param);
  mp_param.max_chunk_size =
          iface->config.tm.max_tags * sizeof(uct_bxi_recv_block_t);
  mp_param.elems_per_chunk = mp_param.max_elems =
          ucs_min(uct_bxi_iface_md(iface)->config.limits.max_entries,
                  iface->config.tm.max_tags);
  mp_param.elem_size   = sizeof(uct_bxi_recv_block_t);
  mp_param.alignment   = UCS_SYS_CACHE_LINE_SIZE;
  mp_param.ops         = &uct_bxi_recv_block_mpool_ops;
  mp_param.name        = "tag-recv-block";
  mp_param.grow_factor = 1;
  status               = ucs_mpool_init(&mp_param, &iface->tm.recv_block_mp);
  if (status != UCS_OK) {
    goto err_release_rxq;
  }

  /* Create RXQ for rendez-vous blocks, see uct_bxi_ep_tag_rndv_zcopy for 
   * details.*/
  rxq_param.flags = UCT_BXI_RXQ_FLAG_EMPTY_MEMPOOL;
  rxq_param.eqh   = iface->rx.eqh;
  rxq_param.nih   = uct_bxi_iface_md(iface)->nih;
  rxq_param.mp    = (uct_iface_mpool_config_t){0};
  rxq_param.name  = "ctrl-tag";
  //NOTE: There are no blocks associated to the RXQ, so no handler.
  rxq_param.handler = NULL;

  status = uct_bxi_rxq_create(&rxq_param, &iface->rx.ctrl.q);
  if (status != UCS_OK) {
    goto err_release_blockrecvmp;
  }

  /* Memory pool of Generic operation. These are counters that are 
   * used to implement dependencies between sends and receives. */
  ucs_mpool_params_reset(&mp_param);
  mp_param.max_chunk_size  = config->tm.gop_mp.max_chunk_size;
  mp_param.elems_per_chunk = config->tm.gop_mp.bufs_grow;
  mp_param.max_elems   = ucs_min(uct_bxi_iface_md(iface)->config.limits.max_cts,
                                 iface->config.tm.max_gop);
  mp_param.elem_size   = sizeof(uct_bxi_gop_t) + iface->config.seg_size;
  mp_param.alignment   = UCS_SYS_CACHE_LINE_SIZE;
  mp_param.ops         = &uct_bxi_gop_mpool_ops;
  mp_param.name        = "gop";
  mp_param.grow_factor = 1;

  status = ucs_mpool_init(&mp_param, &iface->tm.gop_mp);
  if (status != UCS_OK) {
    goto err_clean_ctrl_rxq;
  }

  return status;

err_clean_ctrl_rxq:
  uct_bxi_rxq_fini(iface->rx.ctrl.q);
err_release_blockrecvmp:
  ucs_mpool_cleanup(&iface->tm.recv_block_mp, 0);
err_release_rxq:
  uct_bxi_rxq_fini(iface->rx.tag.q);
err:
  return status;
}

void uct_bxi_iface_tag_fini(uct_bxi_iface_t *iface)
{
  void               *recv_buffer;
  uct_bxi_rndv_cnt_t *cnt;

  if (!iface->tm.enabled) {
    goto out;
  }

  kh_foreach_key (&iface->tm.tag_addrs, recv_buffer, {
    ucs_debug("destroying iface %p, with recv buffer %p offloaded to the HW",
              iface, recv_buffer);
  })
    ;
  kh_destroy_inplace(uct_bxi_tag_addrs, &iface->tm.tag_addrs);

  kh_foreach_key (&iface->tm.conn_map, cnt, {
    ucs_warn("BXI: unassigned rndv counter. cnt=%p", cnt);
    ucs_free(cnt);
  })
    ;

  kh_destroy_inplace(uct_bxi_conn_map, &iface->tm.conn_map);

  /* Release TAG RX queue. */
  uct_bxi_rxq_fini(iface->rx.tag.q);
  uct_bxi_rxq_fini(iface->rx.ctrl.q);

  /* Receive block memory pool.*/
  ucs_mpool_cleanup(&iface->tm.recv_block_mp, 1);
  /* And operation contexts.*/
  ucs_mpool_cleanup(&iface->tm.gop_mp, 1);

out:
  return;
}
