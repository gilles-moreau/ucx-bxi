#include "bxi_conn.h"
#include "bxi_iface.h"
#include "bxi_rxq.h"

ucs_status_t uct_bxi_conn_insert(uct_bxi_iface_t *iface, uct_bxi_conn_t *conn,
                                 uct_bxi_recv_block_t *block, ptl_event_t *ev,
                                 uct_bxi_block_handler handler, uint16_t sn)
{
  ucs_status_t             status = UCS_OK;
  ucs_frag_list_ooo_type_t err;
  uct_bxi_conn_ooo_t      *ooo, *ooo_tmp;
  ucs_frag_list_elem_t    *elem;

  ooo = ucs_mpool_get(&conn->ooo_mp);
  ucs_assert(ooo != NULL);

  /* Init ooo data, only needed if message is ooo. */
  ooo->block   = block;
  ooo->handler = handler; //FIXME: will always be block handler? Then no
                          //       need to pass it as argument.
  ooo->initiator  = ev->initiator;
  ooo->start      = ev->start;
  ooo->mlength    = ev->mlength;
  ooo->rlength    = ev->rlength;
  ooo->hdr_data   = ev->hdr_data;
  ooo->match_bits = ev->match_bits;

  /* Try inserting with sequence number. */
  err = ucs_frag_list_insert(&conn->ooo_q, &ooo->elem, sn);
  if (ucs_likely(err == UCS_FRAG_LIST_INSERT_FAST)) {
    /* Message arrived in order, thus invoke handler. */
    status = ooo->handler(iface, conn, ooo->block, ooo);
    if (status != UCS_OK) {
      ucs_error("BXI: handle failed.");
      goto err;
    }
    ucs_mpool_put(ooo);
  } else if ((err == UCS_FRAG_LIST_INSERT_FIRST) ||
             (err == UCS_FRAG_LIST_INSERT_READY)) {
    /* Delayed message arrived, invoke its handler... */
    status = ooo->handler(iface, conn, ooo->block, ooo);
    if (status != UCS_OK) {
      ucs_error("BXI: handle failed.");
      goto err;
    }
    ucs_mpool_put(ooo);

    /* ... and handlers of out-of-order messages. */
    while ((elem = ucs_frag_list_pull(&conn->ooo_q)) != NULL) {
      ooo_tmp = ucs_container_of(elem, uct_bxi_conn_ooo_t, elem);

      status = ooo_tmp->handler(iface, conn, ooo_tmp->block, ooo_tmp);
      if (status != UCS_OK) {
        ucs_error("BXI: handle failed.");
        goto err;
      }

      if ((--block->pending_ooo == 0) &&
          block->flags & UCT_BXI_RECV_BLOCK_FLAG_PENDING_LINK) {
        status = uct_bxi_recv_block_unexp_activate(block);
        goto err;
      }

      ucs_mpool_put(ooo_tmp);
    }
  } else if (err == UCS_FRAG_LIST_INSERT_SLOW) {
    block->pending_ooo++;
  } else if (err == UCS_FRAG_LIST_INSERT_FAIL) {
    ucs_error("BXI: failed msg inserted. sn=%d", sn);
    status = UCS_ERR_IO_ERROR;
  }

err:
  return status;
}

uct_bxi_conn_t *uct_bxi_conn_get(uct_bxi_iface_t *iface, uct_bxi_conn_id_t *id)
{
  khiter_t iter;

  iter = kh_get(uct_bxi_conn_map, &iface->conn_map, id);
  if (ucs_likely(iter != kh_end(&iface->conn_map))) {
    return kh_value(&iface->conn_map, iter);
  }

  return NULL;
}

static ucs_mpool_ops_t uct_bxi_ooo_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = NULL,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

ucs_status_t uct_bxi_conn_reset(uct_bxi_iface_t *iface, uct_bxi_conn_t *conn)
{
  ucs_frag_list_cleanup(&conn->ooo_q);
  return ucs_frag_list_init(0, &conn->ooo_q,
                            -1 UCS_STATS_ARG(iface->super.stats));
}

ucs_status_t uct_bxi_conn_create(uct_bxi_iface_t *iface, uct_bxi_conn_id_t id,
                                 uct_bxi_conn_t **conn_p)
{
  ucs_status_t       status;
  int                ret;
  khiter_t           iter;
  uct_bxi_conn_t    *conn;
  ucs_mpool_params_t mp_params;

  conn = ucs_malloc(sizeof(uct_bxi_conn_t), "bxi conn");
  if (conn == NULL) {
    ucs_error("BXI: failed to allocate bxi endpoint connection.");
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }
  conn->flags = 0;

  conn->id.pid      = id.pid;
  conn->id.pti      = id.pti;
  conn->id.conn_key = id.conn_key;

  iter = kh_put(uct_bxi_conn_map, &iface->conn_map, &conn->id, &ret);
  ucs_assertv((ret != UCS_KH_PUT_FAILED), "ret %d", ret);

  /* Get the connection or create it if it does not exist and add 
   * it to the hash table. */
  if (ret == UCS_KH_PUT_KEY_PRESENT) {
    ucs_free(conn);
    conn = kh_value(&iface->conn_map, iter);
    ucs_debug("BXI: conn already exists. nid=%d, pid=%d, pti=%d, conn key=%d.",
              conn->id.pid.phys.nid, conn->id.pid.phys.pid, conn->id.pti,
              conn->id.conn_key);
    status = UCS_OK;
    goto out;
  }

  /* Initialize counters. */
  conn->my_pti = iface->tm.enabled ? iface->rx.ctrl.q->pti : iface->rx.rma.pti;

  /* Initialize Out-of-Order list. */
  status = ucs_frag_list_init(0, &conn->ooo_q,
                              -1 UCS_STATS_ARG(iface->super.stats));
  if (status != UCS_OK) {
    ucs_error("BXI: could not allocate frag list.");
    goto err_free_conn;
  }

  /* Initialize MP of Out-of-order operation */
  ucs_mpool_params_reset(&mp_params);
  mp_params.max_chunk_size =
          iface->config.max_events * sizeof(uct_bxi_conn_ooo_t);
  mp_params.elems_per_chunk = iface->config.max_events;
  mp_params.elem_size       = sizeof(uct_bxi_conn_ooo_t);
  mp_params.max_elems       = iface->config.max_events;
  mp_params.alignment       = UCS_SYS_CACHE_LINE_SIZE;
  mp_params.align_offset    = sizeof(uct_bxi_conn_ooo_t);
  mp_params.ops             = &uct_bxi_ooo_mpool_ops;
  mp_params.name            = "ooo-mp";
  mp_params.grow_factor     = 1.0;

  status = ucs_mpool_init(&mp_params, &conn->ooo_mp);
  if (status != UCS_OK) {
    goto err_free_fraglist;
  }

  kh_value(&iface->conn_map, iter) = conn;

  ucs_debug("BXI: created conn. iface=%p, nid=%d, pid=%d, pti=%d, conn key=%d.",
            iface, id.pid.phys.nid, id.pid.phys.pid, id.pti, id.conn_key);

out:
  conn->sn = conn->send = conn->recv = 1;

  *conn_p = conn;

  return status;

err_free_fraglist:
  ucs_frag_list_cleanup(&conn->ooo_q);
err_free_conn:
  ucs_free(conn);
err:
  return status;
}

void uct_bxi_conn_delete(uct_bxi_conn_t *conn)
{
  ucs_frag_list_cleanup(&conn->ooo_q);
  ucs_mpool_cleanup(&conn->ooo_mp, 0);
  ucs_free(conn);
}
