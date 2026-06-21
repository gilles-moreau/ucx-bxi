#include <portals4.h>
#include <unistd.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "bxi.h"
#include "bxi_ep.h"
#include "bxi_iface.h"

#include <ucs/sys/math.h>

#define UCT_BXI_IFACE_MAX_EPS  8192
#define UCT_BXI_IFACE_OVERHEAD 75e-9
#define UCT_BXI_IFACE_LATENCY  ucs_linear_func_make(1000e-9, 0)

static uct_iface_ops_t     uct_bxi_iface_tl_ops;
static uct_bxi_iface_ops_t uct_bxi_iface_ops;

static char *uct_bxi_event_str[] = {
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

ucs_config_field_t uct_bxi_iface_config_table[] = {
        {"", "ALLOC=heap;MAX_NUM_EPS=1024", NULL,
         ucs_offsetof(uct_bxi_iface_config_t, super),
         UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},

        {"MAX_EVENTS", "2048",
         "Maximum number of events per event queue (default: 2048).",
         ucs_offsetof(uct_bxi_iface_config_t, max_events),
         UCS_CONFIG_TYPE_UINT},

        {"MAX_TX_QUEUE_LEN", "1024",
         "Maximum number of outstanding operations (default: 1024).",
         ucs_offsetof(uct_bxi_iface_config_t, tx.max_queue_len),
         UCS_CONFIG_TYPE_UINT},

        UCT_IFACE_MPOOL_CONFIG_FIELDS(
                "TX_", -1, 128, 128m, 1.0, "send",
                ucs_offsetof(uct_bxi_iface_config_t, tx.mp), "\n"),

        {"MAX_RX_QUEUE_LEN", "128",
         "Maximum number of bounced blocks in the Receive Queue (default: "
         "128).",
         ucs_offsetof(uct_bxi_iface_config_t, rx.max_queue_len),
         UCS_CONFIG_TYPE_UINT},

        {"NUM_RX_SEG", "1024",
         "Number of segments per receive block in the RX Queue (default: 1024)",
         ucs_offsetof(uct_bxi_iface_config_t, rx.num_seg),
         UCS_CONFIG_TYPE_UINT},

        UCT_IFACE_MPOOL_CONFIG_FIELDS(
                "RX_AM_", -1, 128, 128m, 1.0, "recv_am",
                ucs_offsetof(uct_bxi_iface_config_t, rx.am_mp), "\n"),

        UCT_IFACE_MPOOL_CONFIG_FIELDS(
                "RX_RMA_", 1, 128, 128m, 1.0, "recv_rma",
                ucs_offsetof(uct_bxi_iface_config_t, rx.rma_mp), "\n"),

        //TODO: difference between seg_size, aka rendezvous threshold, and the
        //      threshold calculated by the protocol selection may result in
        //      breaking send/receiver symmetry. The latter is required to correctly
        //      execute triggered operations.
        //      Example: seg size=8192 and protocol threshold=8184. If msg size=8192,
        //      send will initiate rendezvous while receive think it will be eager.
        //      As a consequence, it will not correctly set the counter threshold for
        //      the triggered operation.
        {"SEG_SIZE", "2048",
         "Size of bounce buffers used for post_send "
         "and post_recv. (default: 8192).",
         ucs_offsetof(uct_bxi_iface_config_t, seg_size),
         UCS_CONFIG_TYPE_MEMUNITS},

        {"TM_ENABLE", "n", "Enable HW tag matching",
         ucs_offsetof(uct_bxi_iface_config_t, tm.enable), UCS_CONFIG_TYPE_BOOL},

        UCT_IFACE_MPOOL_CONFIG_FIELDS(
                "RX_TAG_", -1, 128, 128m, 1.0, "recv_tag",
                ucs_offsetof(uct_bxi_iface_config_t, rx.tag_mp),
                "Memory pool of bounced buffers posted in the Portals overflow "
                "list.\n"),

        {"MAX_TM_OP_CTX", "256",
         "Maximum number of tag matching generic operation (default: 256).",
         ucs_offsetof(uct_bxi_iface_config_t, tm.max_gop),
         UCS_CONFIG_TYPE_UINT},

        UCT_IFACE_MPOOL_CONFIG_FIELDS(
                "TM_OP_CTX_", -1, 32, 128m, 1.0, "tm_gop",
                ucs_offsetof(uct_bxi_iface_config_t, tm.gop_mp), "\n"),

        {"TM_LIST_SIZE", "256",
         "Limits the number of tags posted to the HW for matching.",
         ucs_offsetof(uct_bxi_iface_config_t, tm.list_size),
         UCS_CONFIG_TYPE_UINT},

        {"MAX_OPERATION_CONTEXT", "1024",
         "Number of operation context allocable (default: 128)",
         ucs_offsetof(uct_bxi_iface_config_t, tm.max_gop),
         UCS_CONFIG_TYPE_UINT},

        {NULL},
};

static ucs_status_t uct_bxi_iface_block_handle_am(uct_bxi_iface_t      *iface,
                                                  uct_bxi_conn_t       *conn,
                                                  uct_bxi_recv_block_t *block,
                                                  uct_bxi_conn_ooo_t   *ooo)
{
  ucs_status_t status = UCS_OK;
  uint8_t      am_id  = UCT_BXI_AM_ID_GET(ooo->hdr_data);

  status = uct_iface_invoke_am(&iface->super, am_id, ooo->start, ooo->mlength,
                               0);

  uct_bxi_iface_trace_am(iface, UCT_AM_TRACE_TYPE_RECV, am_id, ooo->start,
                         ooo->mlength);

err:
  return status;
}

static unsigned uct_bxi_iface_poll_rx(uct_bxi_iface_t *iface)
{
  ucs_status_t          status     = UCS_OK;
  unsigned              progressed = 0;
  ptl_event_t           ev;
  int                   ret;
  uct_bxi_recv_block_t *block;
  uct_bxi_conn_t       *conn;
  uint16_t              sn;
  uct_bxi_conn_id_t     id = {0};
  uct_bxi_conn_ooo_t    ooo;

  while (1) {
    ret = PtlEQGet(iface->rx.eqh, &ev);

    switch (ret) {
    case PTL_OK:
      ucs_debug("BXI: RX event. iface=%p, type=%s, size=%lu, start=%p, pti=%d, "
                "block=%p, nid=%d, pid=%d, match bits=%lx",
                iface, uct_bxi_event_str[ev.type], ev.mlength, ev.start,
                ev.pt_index, ev.user_ptr, ev.initiator.phys.nid,
                ev.initiator.phys.pid, ev.match_bits);

      block = (uct_bxi_recv_block_t *)ev.user_ptr;

      switch (ev.type) {
      case PTL_EVENT_PUT:
      case PTL_EVENT_PUT_OVERFLOW:
        /* Fetch endpoint connection to get out-of-order list. */
        id.pid      = ev.initiator;
        id.pti      = UCT_BXI_CONN_PTI_GET(ev.hdr_data);
        id.conn_key = UCT_BXI_CONN_KEY_GET(ev.hdr_data);
        conn        = uct_bxi_conn_get(iface, id);
        if (ucs_unlikely(conn == NULL)) {
          status = uct_bxi_conn_create(iface, id, &conn);
          if (status != UCS_OK) {
            goto out;
          }
        }

        /* Insert to connection frag list to handle out-of-order messages. 
         * Handler is called if messages arrived in order. */
        sn     = UCT_BXI_CONN_SN_GET(ev.hdr_data);
        status = uct_bxi_conn_insert(iface, conn, block, &ev, block->handler,
                                     sn);
        if (status != UCS_OK) {
          goto out;
        }
        break;
      case PTL_EVENT_GET:
        /* GET are not subject to out-of-order check.*/
        ooo.hdr_data   = ev.hdr_data;
        ooo.match_bits = ev.match_bits;
        ooo.mlength    = ev.mlength;
        ooo.rlength    = ev.rlength;
        ooo.start      = ev.start;

        status = block->handler(iface, conn, block, &ooo);
        break;
      case PTL_EVENT_AUTO_UNLINK:
        /* A receive block from the PTL_OVERFLOW_LIST has been filled. 
         * Link it back, all included data has been processed already. */
        status = uct_bxi_recv_block_unexp_activate(block);
        break;
      case PTL_EVENT_AUTO_FREE:
        /* AUTO_FREE are generated for on TAG RXQ because block are posted 
         * on the OVERFLOW_LIST. However, there is nothing to do here. */
        break;
      case PTL_EVENT_PT_DISABLED:
        ucs_error("BXI: event %s. Control flow not implemented.",
                  uct_bxi_event_str[ev.type]);
        status = UCS_ERR_IO_ERROR;
        goto out;
        break;
      case PTL_EVENT_LINK:
        block->flags |= UCT_BXI_RECV_BLOCK_FLAG_LINKED;
        goto out;
        break;
      case PTL_EVENT_GET_OVERFLOW:
      case PTL_EVENT_ACK:
      case PTL_EVENT_REPLY:
      case PTL_EVENT_ATOMIC:
      case PTL_EVENT_FETCH_ATOMIC:
      case PTL_EVENT_FETCH_ATOMIC_OVERFLOW:
      case PTL_EVENT_ATOMIC_OVERFLOW:
      case PTL_EVENT_SEARCH:
      case PTL_EVENT_SEND:
        ucs_error("PTL: event %s should not have been triggered",
                  uct_bxi_event_str[ev.type]);
        status = UCS_ERR_IO_ERROR;
        goto out;
        break;
      default:
        break;
      }

      if (status != UCS_OK) {
        goto out;
      }

      progressed++;

      break;
    case PTL_EQ_EMPTY:
      goto out;
      break;
    case PTL_EQ_DROPPED:
      ucs_error("BXI: EQ event dropped.");
      goto out;
      break;
    default:
      uct_bxi_rc_log(ret);
      goto out;
    }
  }

out:
  return progressed;
}

ucs_status_t uct_bxi_iface_query(uct_iface_h uct_iface, uct_iface_attr_t *attr)
{
  uct_bxi_iface_t *iface = ucs_derived_of(uct_iface, uct_bxi_iface_t);

  uct_base_iface_query(&iface->super, attr);

  attr->cap.am.max_short = iface->config.max_inline;
  attr->cap.am.max_bcopy = iface->config.seg_size;
  attr->cap.am.max_zcopy = 0;
  attr->cap.am.max_iov   = iface->config.max_iovecs;

  attr->cap.put.max_short       = iface->config.max_inline;
  attr->cap.put.max_bcopy       = iface->config.seg_size;
  attr->cap.put.min_zcopy       = 0;
  attr->cap.put.max_zcopy       = iface->config.max_msg_size;
  attr->cap.put.max_iov         = iface->config.max_iovecs;
  attr->cap.put.opt_zcopy_align = 1;
  attr->cap.put.align_mtu       = attr->cap.put.opt_zcopy_align;

  attr->cap.get.max_short       = iface->config.max_inline;
  attr->cap.get.max_bcopy       = iface->config.seg_size;
  attr->cap.get.min_zcopy       = 0;
  attr->cap.get.max_zcopy       = iface->config.max_msg_size;
  attr->cap.get.max_iov         = iface->config.max_iovecs;
  attr->cap.get.opt_zcopy_align = 1;
  attr->cap.get.align_mtu       = attr->cap.get.opt_zcopy_align;

  attr->ep_addr_len     = iface->config.ep_addr_size;
  attr->iface_addr_len  = iface->config.iface_addr_size;
  attr->device_addr_len = iface->config.device_addr_size;

  //FIXME: implementing AM_SHORT requires to have one pending queue per
  //       endpoint which implies some changes in the way resource are
  //       managed.
  attr->cap.flags = UCT_IFACE_FLAG_AM_BCOPY | UCT_IFACE_FLAG_PUT_BCOPY |
                    UCT_IFACE_FLAG_GET_BCOPY |
#if !HAVE_BXI3_R6LITE
                    UCT_IFACE_FLAG_PUT_SHORT |
#endif
                    UCT_IFACE_FLAG_PUT_ZCOPY | UCT_IFACE_FLAG_GET_ZCOPY |
                    UCT_IFACE_FLAG_PENDING | UCT_IFACE_FLAG_CB_SYNC |
                    UCT_IFACE_FLAG_INTER_NODE |
                    UCT_IFACE_FLAG_CONNECT_TO_IFACE | UCT_IFACE_FLAG_EP_CHECK;

  //TODO: UCT_IFACE_FLAG_ERRHANDLE_ZCOPY_BUF: currently not handled by Portals4
  //      simulator. A kernel segfault is raised instead of ni_fail_type set to
  //      PTL_NI_SEGV in a event.
  //TODO: IFACE_ALIGNMENT: UCT test related to alignment have been skipped. Check
  //      if this could be implemented in BXI. It seems related to how receive
  //      descriptor are registered. LOCAL_MANAGE option may prevent the reception
  //      of aligned data. It also seems that UCS_CB_PARAM_FLAG_DESC is required,
  //      which means that the receive descriptor may not be returned directly to
  //      UCT layer.
  //TODO: TEST UCT PEER FAILURE: UCT_IFACE_AM_SHORT is needed to support
  //      UCT_IFACE_FLAG_ERRHANDLE_PEER_FAILURE.

#if !HAVE_BXI3_R6LITE
  attr->cap.atomic32.op_flags |=
          UCS_BIT(UCT_ATOMIC_OP_ADD) | UCS_BIT(UCT_ATOMIC_OP_AND) |
          UCS_BIT(UCT_ATOMIC_OP_XOR) | UCS_BIT(UCT_ATOMIC_OP_OR) |
          UCS_BIT(UCT_ATOMIC_OP_CSWAP);
  attr->cap.atomic32.fop_flags |=
          UCS_BIT(UCT_ATOMIC_OP_ADD) | UCS_BIT(UCT_ATOMIC_OP_AND) |
          UCS_BIT(UCT_ATOMIC_OP_XOR) | UCS_BIT(UCT_ATOMIC_OP_OR) |
          UCS_BIT(UCT_ATOMIC_OP_CSWAP);
  attr->cap.atomic64.op_flags |=
          UCS_BIT(UCT_ATOMIC_OP_ADD) | UCS_BIT(UCT_ATOMIC_OP_AND) |
          UCS_BIT(UCT_ATOMIC_OP_XOR) | UCS_BIT(UCT_ATOMIC_OP_OR) |
          UCS_BIT(UCT_ATOMIC_OP_CSWAP);
  attr->cap.atomic64.fop_flags |=
          UCS_BIT(UCT_ATOMIC_OP_ADD) | UCS_BIT(UCT_ATOMIC_OP_AND) |
          UCS_BIT(UCT_ATOMIC_OP_XOR) | UCS_BIT(UCT_ATOMIC_OP_OR) |
          UCS_BIT(UCT_ATOMIC_OP_CSWAP);
#endif

  attr->latency             = UCT_BXI_IFACE_LATENCY;
  attr->bandwidth.dedicated = 0;
  attr->bandwidth.shared    = 10 * UCS_GBYTE;
  attr->overhead            = UCT_BXI_IFACE_OVERHEAD;
  attr->priority            = 1;

  if (!iface->tm.enabled) {
    return UCS_OK;
  }

  attr->cap.tag.recv.max_outstanding = iface->config.tm.max_tags;
  attr->cap.tag.recv.max_zcopy       = iface->config.max_msg_size;
  attr->cap.tag.recv.max_iov         = 1;
  attr->cap.tag.recv.min_recv        = 0;

  attr->cap.tag.eager.max_short = iface->config.max_inline;
  attr->cap.tag.eager.max_bcopy = iface->config.seg_size;
  //FIXME: UCP layer uses ucs_alloca to allocate the receive descriptor
  //       which is limited in size (1200). This is only used in the sync
  //       path. In order to increase this threshold, we need to support the
  //       UCT_CB_PARAM_FLAG_DESC flags so that the descriptor may be
  //       kept by UCP to save protocol information in it. Indeed, the ack needs
  //       to be sent only when the match happened. One requirement
  //       is to leave a headroom in the receive descriptors and support
  //       UCS_INPROGRESS return call from invoke_am_callback. However, RXQ
  //       option with MANAGE_LOCAL are not suitable has there are no way to
  //       leave space for this headroom...
  attr->cap.tag.eager.max_zcopy = iface->config.seg_size;
  attr->cap.tag.eager.max_iov   = iface->config.max_iovecs;
  attr->cap.tag.rndv.max_hdr    = iface->config.tm.max_hdr;
  attr->cap.tag.rndv.max_iov    = iface->config.max_iovecs;
  attr->cap.tag.rndv.max_zcopy  = iface->config.max_msg_size;

  attr->cap.flags |=
          UCT_IFACE_FLAG_TAG_EAGER_SHORT | UCT_IFACE_FLAG_TAG_EAGER_BCOPY |
          UCT_IFACE_FLAG_TAG_EAGER_ZCOPY | UCT_IFACE_FLAG_TAG_RNDV_ZCOPY |
          UCT_IFACE_FLAG_TAG_OFFLOAD_OP | UCT_IFACE_FLAG_CONNECT_WITH_KEY;

  return UCS_OK;
}

static ucs_status_t uct_bxi_iface_get_addr(uct_iface_h       tl_iface,
                                           uct_iface_addr_t *tl_addr)
{
  uct_bxi_iface_addr_t *addr  = (void *)tl_addr;
  uct_bxi_iface_t      *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);

  addr->rma  = iface->rx.rma.pti;
  addr->am   = uct_bxi_rxq_get_addr(iface->rx.am.q);
  addr->tag  = !iface->tm.enabled ? UCT_BXI_PT_NULL :
                                    uct_bxi_rxq_get_addr(iface->rx.tag.q);
  addr->ctrl = !iface->tm.enabled ? UCT_BXI_PT_NULL :
                                    uct_bxi_rxq_get_addr(iface->rx.ctrl.q);

  return UCS_OK;
}

ucs_status_t uct_bxi_iface_get_device_address(uct_iface_h        tl_iface,
                                              uct_device_addr_t *tl_addr)
{
  uct_bxi_device_addr_t *addr  = (void *)tl_addr;
  uct_bxi_iface_t       *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);

  addr->pid = uct_bxi_iface_md(iface)->pid;

  return UCS_OK;
}

static inline void uct_bxi_iface_handle_tx_failure(uct_bxi_iface_t *iface,
                                                   uct_bxi_iface_send_op_t *op)
{
  ucs_status_t status = UCS_ERR_ENDPOINT_TIMEOUT;

  /* Don't remove operation from outstanding list, it will be done later. */

  /* Close endpoint. */
  op->ep->conn_state = UCT_BXI_EP_CONN_CLOSED;

  status = uct_iface_handle_ep_err(&iface->super.super, &op->ep->super.super,
                                   status);

  ucs_error("BXI: operation failed. op=%p, ep=%p", op, op->ep);

  ucs_assert(status == UCS_OK);
}

static UCS_F_ALWAYS_INLINE void uct_bxi_iface_check_flush(uct_bxi_ep_t *ep)
{
  uct_bxi_iface_send_op_t *op, *tmp;

  /* Endpoint may be null for rndv get operation. */
  if (ep == NULL) {
    return;
  }

  /* Loop on operation queue and complete all flush operations: flush is 
   * completed when there are no send operation before. */
  ucs_list_for_each_safe (op, tmp, &ep->send_ops, elem) {
    if (op->flags & UCT_BXI_IFACE_SEND_OP_FLAG_FLUSH) {
      UCT_TL_EP_STAT_FLUSH(&ep->super);
      uct_bxi_iface_completion_flush_op(op);
    } else if (op->flags & UCT_BXI_IFACE_SEND_OP_FLAG_FENCE) {
      UCT_TL_EP_STAT_FENCE(&ep->super);
      uct_bxi_iface_completion_flush_op(op);
    } else {
      break;
    }
  }
}

static UCS_F_ALWAYS_INLINE int
uct_bxi_iface_op_is_inlined(uct_bxi_iface_t *iface, ptl_size_t length)
{
  return length <= iface->config.max_inline;
}

/* Poll tx is both used for interface progression. Only events 
 * on initiator side are PTL_EVENT_SEND, PTL_EVENT_ACK and 
 * PTL_EVENT_REPLY. */
unsigned uct_bxi_iface_poll_tx(uct_bxi_iface_t *iface)
{
  unsigned                      progressed = 0;
  uct_bxi_iface_send_op_t      *op;
  int                           ret;
  ptl_event_t                   ev;
  uct_bxi_ep_t                 *ep;
  uct_pending_req_priv_queue_t *priv;

  while (1) {
    ret = PtlEQGet(iface->tx.eqh, &ev);

    op = ev.user_ptr;

    switch (ret) {
    case PTL_OK:
      ucs_trace("BXI: TX event. iface=%p, type=%s, size=%lu, available=%lu, "
                "op=%p",
                iface, uct_bxi_event_str[ev.type], ev.mlength,
                iface->tx.available, ev.user_ptr);
      switch (ev.type) {
      case PTL_EVENT_REPLY:
        /* This event is generated after TAG GET operation completion. */
        if (ev.mlength > 0 && uct_bxi_iface_op_is_inlined(iface, ev.mlength) &&
            uct_bxi_ep_is_intra_node(op->ep)) {
          //NOTE: for small size messages, host memory may not be coherent with
          //      completion of the operation, thus force NIC synchronization.
          //TODO: test with PTL_MD_VOLATILE unset
          PtlAtomicSync();
        }
        // Fallthrough
      case PTL_EVENT_ACK:
        progressed++;
        if (ev.ni_fail_type != PTL_NI_OK) {
          uct_bxi_iface_handle_tx_failure(iface, op);
        }
        uct_bxi_iface_completion_op(op);
        break;
      case PTL_EVENT_SEND:
      case PTL_EVENT_PUT:
      case PTL_EVENT_AUTO_UNLINK:
      case PTL_EVENT_PUT_OVERFLOW:
      case PTL_EVENT_LINK:
      case PTL_EVENT_GET_OVERFLOW:
      case PTL_EVENT_GET:
      case PTL_EVENT_AUTO_FREE:
      case PTL_EVENT_ATOMIC:
      case PTL_EVENT_FETCH_ATOMIC:
      case PTL_EVENT_SEARCH:
      case PTL_EVENT_FETCH_ATOMIC_OVERFLOW:
      case PTL_EVENT_ATOMIC_OVERFLOW:
      case PTL_EVENT_PT_DISABLED:
        ucs_fatal("BXI: event %s should not have been triggered",
                  uct_bxi_event_str[ev.type]);
        break;
      default:
        break;
      }
      break;
    case PTL_EQ_EMPTY:
      goto out;
      break;
    case PTL_EQ_DROPPED:
      ucs_error("BXI: EQ event dropped.");
      goto out;
      break;
    default:
      uct_bxi_rc_log(ret);
      progressed = 0;
      goto out;
    }
  }

out:
  /* With new credits available, dispatch pending queue and flush/fence 
   * operations. */
  ucs_list_for_each (ep, &iface->eps, elem) {
    uct_pending_queue_dispatch(priv, &ep->pending_q, 1);
    uct_bxi_iface_check_flush(ep);
  }

  return progressed;
}

unsigned uct_bxi_iface_progress(uct_iface_t *super)
{
  unsigned         count;
  uct_bxi_iface_t *iface = ucs_derived_of(super, uct_bxi_iface_t);

  count = uct_bxi_iface_poll_rx(iface);
  if (!uct_bxi_iface_should_poll_tx(count)) {
    return count;
  }

  return uct_bxi_iface_poll_tx(iface);
}

//NOTE: Current flush semantic is the following: a flush operation is completed
//      when all previous operations on the interface memory descriptor have been
//      acked. In practice, this corresponds to UCT_FLUSH_FLAG_REMOTE.
//      Wouldn't the event PTL_EVENT_SEND be the correct event to check in terms
//      of semantics?
ucs_status_t uct_bxi_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                 uct_completion_t *comp)
{
  ucs_status_t     status;
  unsigned         count = 0;
  uct_bxi_ep_t    *ep;
  uct_bxi_iface_t *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);

  if (comp != NULL) {
    return UCS_ERR_UNSUPPORTED;
  }

  ucs_list_for_each (ep, &iface->eps, elem) {
    status = uct_bxi_ep_flush(&ep->super.super, 0, NULL);
    if ((status == UCS_ERR_NO_RESOURCE) || (status == UCS_INPROGRESS)) {
      count++;
    } else if (status != UCS_OK) {
      return status;
    }
  }

  if (count != 0) {
    UCT_TL_IFACE_STAT_FLUSH_WAIT(&iface->super);
    return UCS_INPROGRESS;
  }

  UCT_TL_IFACE_STAT_FLUSH(&iface->super);
  return UCS_OK;
}

ucs_status_t uct_bxi_iface_fence(uct_iface_h tl_iface, unsigned flags)
{
  uct_bxi_iface_t *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);
  unsigned         count = 0;
  ucs_status_t     status;
  uct_bxi_ep_t    *ep;

  ucs_list_for_each (ep, &iface->eps, elem) {
    status = uct_bxi_ep_fence(&ep->super.super, 0);
    if (status == UCS_ERR_NO_RESOURCE) {
      count++;
    } else if (status != UCS_OK) {
      return status;
    }
  }

  if (count != 0) {
    return status;
  }

  UCT_TL_IFACE_STAT_FENCE(&iface->super);
  return UCS_OK;
}

ucs_status_t
uct_bxi_iface_query_tl_devices(uct_md_h                   uct_md,
                               uct_tl_device_resource_t **tl_devices_p,
                               unsigned                  *num_tl_devices_p)
{
  uct_bxi_md_t *md = ucs_derived_of(uct_md, uct_bxi_md_t);
  return uct_single_device_resource(uct_md, md->device, UCT_DEVICE_TYPE_NET,
                                    md->sys_dev, tl_devices_p,
                                    num_tl_devices_p);
}

static inline void
uct_bxi_iface_config_init(uct_bxi_iface_t              *iface,
                          const uct_bxi_iface_config_t *config)
{
  uct_bxi_md_t *md = uct_bxi_iface_md(iface);

  iface->config.max_num_eps      = config->super.max_num_eps;
  iface->config.max_events       = config->max_events;
  iface->config.seg_size         = config->seg_size;
  iface->config.tx.max_queue_len = config->tx.max_queue_len;
  iface->config.rx.max_queue_len = config->rx.max_queue_len;
  iface->config.rx.num_seg       = config->rx.num_seg;
  //NOTE: There can only be as many ACK in the EQ as the maximal number of
  //      outstanding operations, which is 2 * max_queue_len. Add + 1 to avoid
  //      generating PT_DISABLED event.
  iface->config.tx.max_events = config->tx.max_queue_len + 1;

  iface->config.rx.am_mp = config->rx.am_mp;
  //FIXME: Memory pool max elements is reset here, thus overwriting initial
  //       configuration. See FIXME comment in rxq_create about Memory Pool
  //       usage.
  iface->config.rx.am_mp.max_bufs = config->rx.max_queue_len;
  iface->config.rx.rma_mp         = config->rx.rma_mp;

  //TODO: implement support for scatter buffer.
  iface->config.max_iovecs       = 1;
  iface->config.max_msg_size     = md->config.limits.max_msg_size;
  iface->config.max_inline       = md->config.limits.max_volatile_size;
  iface->config.device_addr_size = sizeof(uct_bxi_device_addr_t);
  iface->config.iface_addr_size  = sizeof(uct_bxi_iface_addr_t);
  iface->config.ep_addr_size     = sizeof(uct_bxi_ep_addr_t);
}

void uct_bxi_iface_send_init(ucs_mpool_t *mp, void *obj, void *chunk)
{
  uct_bxi_iface_send_op_t *op = obj;
  uct_bxi_iface_t         *iface =
          ucs_container_of(mp, uct_bxi_iface_t, tx.send_desc_mp);

  op->iface = iface;
  op->flags = 0;
}

static ucs_mpool_ops_t uct_bxi_send_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = uct_bxi_iface_send_init,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

void uct_bxi_iface_send_comp_init(ucs_mpool_t *mp, void *obj, void *chunk)
{
  uct_bxi_iface_send_op_t *op = obj;
  uct_bxi_iface_t *iface = ucs_container_of(mp, uct_bxi_iface_t, tx.send_op_mp);

  op->iface = iface;
  op->flags = 0;
}

static ucs_mpool_ops_t uct_bxi_send_comp_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = uct_bxi_iface_send_comp_init,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

void uct_bxi_iface_send_flush_init(ucs_mpool_t *mp, void *obj, void *chunk)
{
  uct_bxi_iface_send_op_t *op = obj;
  uct_bxi_iface_t         *iface =
          ucs_container_of(mp, uct_bxi_iface_t, tx.flush_ops_mp);

  op->iface = iface;
  op->flags = 0;
}

static ucs_mpool_ops_t uct_bxi_send_flush_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = uct_bxi_iface_send_flush_init,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

static ucs_mpool_ops_t uct_bxi_pending_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = NULL,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

static ucs_status_t uct_bxi_iface_tx_ops_init(uct_bxi_iface_t        *iface,
                                              uct_bxi_iface_config_t *config)
{
  ucs_status_t       status;
  ucs_mpool_params_t mp_params;

  /* Allocate memory pool of TX send operations without buffer. */
  ucs_mpool_params_reset(&mp_params);
  mp_params.max_chunk_size =
          config->tx.mp.max_chunk_size * sizeof(uct_bxi_iface_send_op_t);
  mp_params.elems_per_chunk = config->tx.mp.bufs_grow;
  mp_params.max_elems       = config->tx.max_queue_len;
  mp_params.elem_size       = sizeof(uct_bxi_iface_send_op_t);
  mp_params.alignment       = UCS_SYS_CACHE_LINE_SIZE;
  mp_params.ops             = &uct_bxi_send_comp_mpool_ops;
  mp_params.name            = "send-comp-ops";
  mp_params.grow_factor     = config->tx.mp.grow_factor;

  status = ucs_mpool_init(&mp_params, &iface->tx.send_op_mp);
  if (status != UCS_OK) {
    goto err;
  }

  /* Allocate memory of flush operations. */
  ucs_mpool_params_reset(&mp_params);
  mp_params.elems_per_chunk = 256;
  mp_params.max_elems       = -1;
  mp_params.elem_size       = sizeof(uct_bxi_iface_send_op_t);
  mp_params.alignment       = UCS_SYS_CACHE_LINE_SIZE;
  mp_params.ops             = &uct_bxi_send_flush_mpool_ops;
  mp_params.name            = "bxi-flush-ops";
  status = ucs_mpool_init(&mp_params, &iface->tx.flush_ops_mp);
  if (status != UCS_OK) {
    goto err_free_sendcompmp;
  }

  return status;

err_free_sendcompmp:
  ucs_mpool_cleanup(&iface->tx.send_op_mp, 1);
err:
  return status;
}

static void uct_bxi_iface_tx_ops_fini(uct_bxi_iface_t *iface)
{

  /* Release memory pool of send completion operations. */
  ucs_mpool_cleanup(&iface->tx.send_op_mp, 1);

  /* Then release flush operations. */
  ucs_mpool_cleanup(&iface->tx.flush_ops_mp, 1);
}

UCS_CLASS_INIT_FUNC(uct_bxi_iface_t, uct_md_h tl_md, uct_worker_h worker,
                    const uct_iface_params_t *params,
                    const uct_iface_config_t *uct_config)
{
  ucs_status_t            status = UCS_OK;
  uct_bxi_md_t           *md;
  uct_bxi_iface_config_t *config =
          ucs_derived_of(uct_config, uct_bxi_iface_config_t);
  uct_bxi_mem_desc_param_t mem_desc_param;
  ucs_mpool_params_t       mp_params;
  uct_bxi_rxq_param_t      rxq_param;
#if HAVE_BXI3_R6LITE
  ptl_le_t le;
#else
  ptl_me_t me;
#endif

  UCS_CLASS_CALL_SUPER_INIT(
          uct_base_iface_t, &uct_bxi_iface_tl_ops, &uct_bxi_iface_ops.super,
          tl_md, worker, params,
          &config->super UCS_STATS_ARG(
                  ((params->field_mask & UCT_IFACE_PARAM_FIELD_STATS_ROOT) &&
                   (params->stats_root != NULL)) ?
                          params->stats_root :
                          NULL) UCS_STATS_ARG(params->mode.device.dev_name));

  md = uct_bxi_iface_md(self);

  /* Initialize all config entries. */
  uct_bxi_iface_config_init(self, config);

  /* Create Event Queue used for RX events. */
  status = uct_bxi_wrap(
          PtlEQAlloc(md->nih, self->config.max_events, &self->rx.eqh));
  if (status != UCS_OK) {
    goto err;
  }

  /* Create RX Queues for AM messages. Block are posted to the Priority List */
  rxq_param.flags = 0;
#if HAVE_BXI3_R6LITE
  rxq_param.options = PTL_LE_OP_PUT | PTL_LE_MANAGE_LOCAL |
                      PTL_LE_EVENT_LINK_DISABLE | PTL_LE_MAY_ALIGN;
#else
  rxq_param.options = PTL_ME_OP_PUT | PTL_ME_MANAGE_LOCAL | PTL_ME_NO_TRUNCATE |
                      PTL_ME_EVENT_LINK_DISABLE | PTL_ME_MAY_ALIGN;
#endif
  rxq_param.eqh      = self->rx.eqh;
  rxq_param.nih      = md->nih;
  rxq_param.mp       = self->config.rx.am_mp;
  rxq_param.list     = PTL_PRIORITY_LIST;
  rxq_param.num_segs = self->config.rx.num_seg;
  rxq_param.seg_size = self->config.seg_size;
  rxq_param.handler  = uct_bxi_iface_block_handle_am;
  rxq_param.name     = "rxq-am";

  status = uct_bxi_rxq_create(&rxq_param, &self->rx.am.q);
  if (status != UCS_OK) {
    goto err_clean_rxevq;
  }

  /* Initialize TAG resources if enabled. */
  status = uct_bxi_iface_tag_init(self, params, config);
  if (status != UCS_OK) {
    goto err_clean_rxq;
  }

  /* Create TX Event Queue that will be used for completion of OP. */
  //FIXME: maybe set a lower number of events for the error queue.
  status = uct_bxi_wrap(
          PtlEQAlloc(md->nih, self->config.tx.max_events, &self->tx.eqh));
  if (status != UCS_OK) {
    goto err_clean_tag;
  }

  /* Before setting TX operations, create the Memory Descriptor that
   * spans the whole virtual memory range. */
  mem_desc_param = (uct_bxi_mem_desc_param_t){
          .eqh    = self->tx.eqh,
          .start  = NULL,
          .cth    = PTL_CT_NONE,
          .length = PTL_SIZE_MAX,
#if HAVE_BXI3_R6LITE
          .options = PTL_MD_EVENT_SEND_DISABLE,
#else
          .options = PTL_MD_EVENT_SEND_DISABLE | PTL_MD_VOLATILE,
#endif
          .flags = UCT_BXI_MEM_DESC_FLAG_ALLOCATE,
  };
  status = uct_bxi_md_mem_desc_create(md, &mem_desc_param, &self->tx.mem_desc);
  if (status != UCS_OK) {
    goto err_clean_txevq;
  }

  /* Allocate buffer for short message. */
  self->tx.short_desc = ucs_malloc(self->config.max_inline, "short-desc");
  if (self->tx.short_desc == NULL) {
    status = UCS_ERR_NO_MEMORY;
    goto err_clean_mem_desc;
  }

  /* Create TX buffers mempool */
  ucs_mpool_params_reset(&mp_params);
  mp_params.max_chunk_size  = config->tx.mp.max_chunk_size;
  mp_params.elems_per_chunk = config->tx.mp.bufs_grow;
  mp_params.elem_size = sizeof(uct_bxi_iface_send_op_t) + self->config.seg_size;
  mp_params.max_elems = config->tx.max_queue_len;
  mp_params.alignment = UCS_SYS_CACHE_LINE_SIZE;
  mp_params.align_offset = sizeof(uct_bxi_iface_send_op_t);
  mp_params.ops          = &uct_bxi_send_mpool_ops;
  mp_params.name         = "send-desc-mp";
  mp_params.grow_factor  = config->tx.mp.grow_factor;

  status = ucs_mpool_init(&mp_params, &self->tx.send_desc_mp);
  if (status != UCS_OK) {
    goto err_clean_short_desc;
  }

  /* Initialize operation for the TX Queue. They are not associated with 
   * a buffer. */
  status = uct_bxi_iface_tx_ops_init(self, config);
  if (status != UCS_OK) {
    goto err_clean_txbuffer;
  }

  /* Create mempool for pending requests. There are no maximum number. */
  ucs_mpool_params_reset(&mp_params);
  mp_params.elem_size       = sizeof(uct_bxi_pending_req_t);
  mp_params.alignment       = 1;
  mp_params.elems_per_chunk = 128;
  mp_params.ops             = &uct_bxi_pending_mpool_ops;
  mp_params.name            = "pending-ops";
  status                    = ucs_mpool_init(&mp_params, &self->tx.pending_mp);
  if (status != UCS_OK) {
    goto err_clean_txops;
  }

  self->num_eps = 0;
  ucs_list_head_init(&self->eps);

  /* Initialize available send credits. */
  uct_bxi_iface_available_set(self, self->config.tx.max_queue_len);

  /* Initialize connection map */
  kh_init_inplace(uct_bxi_conn_map, &self->conn_map);
  /* Create RX Queues for RMA messages. Only a single block with events. */

  /* Initialize Portals Table Entry for RDMA operations. */
  status = uct_bxi_wrap(PtlPTAlloc(md->nih, PTL_PT_FLOWCTRL, self->rx.eqh,
                                   PTL_PT_ANY, &self->rx.rma.pti));
  if (status != UCS_OK) {
    goto err_clean_pending;
  }

#if HAVE_BXI3_R6LITE
  le.ct_handle = PTL_CT_NONE;
  le.uid       = PTL_UID_ANY;
  le.start     = NULL;
  le.length    = PTL_SIZE_MAX;
  le.options   = PTL_LE_OP_PUT | PTL_LE_OP_GET | PTL_LE_EVENT_LINK_DISABLE |
               PTL_LE_EVENT_UNLINK_DISABLE | PTL_LE_EVENT_COMM_DISABLE;

  /* RDMA operations are always matched on the same silent ME. */
  status = uct_bxi_wrap(PtlLEAppend(md->nih, self->rx.rma.pti, &le,
                                    PTL_PRIORITY_LIST, NULL,
                                    &self->rx.rma.entry.leh));
#else
  me.ct_handle         = PTL_CT_NONE;
  me.match_bits        = 0;
  me.ignore_bits       = ~0;
  me.match_id.phys.nid = PTL_NID_ANY;
  me.match_id.phys.pid = PTL_PID_ANY;
  me.min_free          = 0;
  me.uid               = PTL_UID_ANY;
  me.start             = NULL;
  me.length            = PTL_SIZE_MAX;
  me.options = PTL_ME_OP_PUT | PTL_ME_OP_GET | PTL_ME_EVENT_LINK_DISABLE |
               PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_EVENT_COMM_DISABLE;

  /* RDMA operations are always matched on the same silent ME. */
  status = uct_bxi_wrap(PtlMEAppend(md->nih, self->rx.rma.pti, &me,
                                    PTL_PRIORITY_LIST, NULL,
                                    &self->rx.rma.entry.meh));
#endif
  if (status != UCS_OK) {
    goto err_clean_rmapti;
  }

  /* PTL hdr is used within internal protocols and 64 bits are needed. Endpoint 
   * hash table uses ptl_process_t supposing it is 8 bytes. */
  ucs_assert(sizeof(uint64_t) <= sizeof(ptl_hdr_data_t));
  ucs_assert(sizeof(uint64_t) <= sizeof(ptl_process_t));

#if HAVE_BXI3_R6LITE
  ucs_debug("BXI: interface info. nih=%s, nid=%d, pid=%d",
            uct_bxi_iface_md(self)->device,
            uct_bxi_iface_md(self)->pid.phys.nid,
            uct_bxi_iface_md(self)->pid.phys.pid);
#else
  ucs_debug("BXI: interface info. nih=%p, nid=%d, pid=%d, eqh=%p",
            uct_bxi_iface_md(self)->nih.handle,
            uct_bxi_iface_md(self)->pid.phys.nid,
            uct_bxi_iface_md(self)->pid.phys.pid, self->rx.eqh.handle);
#endif

  ucs_debug("BXI: interface pti. pti am=%d, pti tag=%d, pti rma=%d, "
            "pti ctrl=%d, eager size=%lu",
            self->rx.am.q->pti,
            self->tm.enabled ? self->rx.tag.q->pti : UCT_BXI_PT_NULL,
            self->rx.rma.pti,
            self->tm.enabled ? self->rx.ctrl.q->pti : UCT_BXI_PT_NULL,
            uct_bxi_iface_md(self)->config.limits.max_waw_ordered_size);

  return status;

err_clean_rmame:
#if HAVE_BXI3_R6LITE
  PtlLEUnlink(self->rx.rma.entry.leh);
#else
  PtlMEUnlink(self->rx.rma.entry.meh);
#endif
err_clean_rmapti:
  PtlPTFree(md->nih, self->rx.rma.pti);
err_clean_pending:
  ucs_mpool_cleanup(&self->tx.pending_mp, 0);
err_clean_txops:
  uct_bxi_iface_tx_ops_fini(self);
err_clean_txbuffer:
  ucs_mpool_cleanup(&self->tx.send_desc_mp, 1);
err_clean_short_desc:
  ucs_free(self->tx.short_desc);
err_clean_mem_desc:
  uct_bxi_md_mem_desc_fini(self->tx.mem_desc);
err_clean_txevq:
  uct_bxi_wrap(PtlEQFree(self->tx.eqh));
err_clean_tag:
  uct_bxi_iface_tag_fini(self);
err_clean_rxq:
  uct_bxi_rxq_fini(self->rx.am.q);
err_clean_rxevq:
  uct_bxi_wrap(PtlEQFree(self->rx.eqh));
err:
  return status;
}

static UCS_CLASS_CLEANUP_FUNC(uct_bxi_iface_t)
{
  uct_bxi_conn_t *conn;
  uct_bxi_md_t   *md = uct_bxi_iface_md(self);

  /* Destroy connection map. Connections and sequence number can outlive 
   * endpoints, so to preserve ordering they must be kept until infterface 
   * destruction. */
  kh_foreach_value (&self->conn_map, conn, { ucs_free(conn); })
    ;
  kh_destroy_inplace(uct_bxi_conn_map, &self->conn_map);

  /* Clean RDMA resources. */
#if HAVE_BXI3_R6LITE
  PtlLEUnlink(self->rx.rma.entry.leh);
#else
  PtlMEUnlink(self->rx.rma.entry.meh);
#endif
  PtlPTFree(md->nih, self->rx.rma.pti);

  /* Clean TX resources. */
  ucs_free(self->tx.short_desc);
  ucs_mpool_cleanup(&self->tx.pending_mp, 1);
  uct_bxi_iface_tx_ops_fini(self);
  ucs_mpool_cleanup(&self->tx.send_desc_mp, 1);
  uct_bxi_md_mem_desc_fini(self->tx.mem_desc);
  PtlEQFree(self->tx.eqh);

  /* Clean RX resources */
  /* Clean TAG resources if enabled. */
  uct_bxi_iface_tag_fini(self);

  uct_base_iface_progress_disable(&self->super.super,
                                  UCT_PROGRESS_SEND | UCT_PROGRESS_RECV);

  /* Clean AM resources */
  uct_bxi_rxq_fini(self->rx.am.q);
  PtlEQFree(self->rx.eqh);

  return;
}

static UCS_CLASS_DECLARE_DELETE_FUNC(uct_bxi_iface_t, uct_iface_t);

static uct_iface_ops_t uct_bxi_iface_tl_ops = {
        .ep_am_short              = uct_bxi_ep_am_short,
        .ep_am_short_iov          = uct_bxi_ep_am_short_iov,
        .ep_am_bcopy              = uct_bxi_ep_am_bcopy,
        .ep_am_zcopy              = uct_bxi_ep_am_zcopy,
        .ep_put_short             = uct_bxi_ep_put_short,
        .ep_put_bcopy             = uct_bxi_ep_put_bcopy,
        .ep_put_zcopy             = uct_bxi_ep_put_zcopy,
        .ep_get_bcopy             = uct_bxi_ep_get_bcopy,
        .ep_get_zcopy             = uct_bxi_ep_get_zcopy,
        .ep_tag_rndv_zcopy        = uct_bxi_ep_tag_rndv_zcopy,
        .ep_tag_eager_zcopy       = uct_bxi_ep_tag_eager_zcopy,
        .ep_tag_eager_bcopy       = uct_bxi_ep_tag_eager_bcopy,
        .ep_tag_eager_short       = uct_bxi_ep_tag_eager_short,
        .ep_tag_rndv_cancel       = uct_bxi_ep_tag_rndv_cancel,
        .ep_tag_rndv_request      = uct_bxi_ep_tag_rndv_request,
        .ep_atomic_cswap64        = uct_bxi_ep_atomic_cswap64,
        .ep_atomic64_post         = uct_bxi_ep_atomic64_post,
        .ep_atomic64_fetch        = uct_bxi_ep_atomic64_fetch,
        .ep_atomic_cswap32        = uct_bxi_ep_atomic_cswap32,
        .ep_atomic32_post         = uct_bxi_ep_atomic32_post,
        .ep_atomic32_fetch        = uct_bxi_ep_atomic32_fetch,
        .ep_pending_add           = uct_bxi_ep_pending_add,
        .ep_pending_purge         = uct_bxi_ep_pending_purge,
        .ep_flush                 = uct_bxi_ep_flush,
        .ep_fence                 = uct_bxi_ep_fence,
        .ep_check                 = uct_bxi_ep_check,
        .ep_create                = UCS_CLASS_NEW_FUNC_NAME(uct_bxi_ep_t),
        .ep_config_key            = uct_bxi_ep_config_key,
        .ep_destroy               = UCS_CLASS_DELETE_FUNC_NAME(uct_bxi_ep_t),
        .ep_get_address           = uct_bxi_ep_get_address,
        .ep_connect_to_ep         = uct_base_ep_connect_to_ep,
        .iface_flush              = uct_bxi_iface_flush,
        .iface_fence              = uct_bxi_iface_fence,
        .iface_progress_enable    = uct_base_iface_progress_enable,
        .iface_progress_disable   = uct_base_iface_progress_disable,
        .iface_progress           = uct_bxi_iface_progress,
        .iface_event_fd_get       = ucs_empty_function_return_unsupported,
        .iface_event_arm          = ucs_empty_function_return_success,
        .iface_close              = UCS_CLASS_DELETE_FUNC_NAME(uct_bxi_iface_t),
        .iface_query              = uct_bxi_iface_query,
        .iface_get_address        = uct_bxi_iface_get_addr,
        .iface_get_device_address = uct_bxi_iface_get_device_address,
        .iface_is_reachable       = uct_base_iface_is_reachable,
        .iface_tag_recv_zcopy     = uct_bxi_iface_tag_recv_zcopy,
        .iface_tag_recv_cancel    = uct_bxi_iface_tag_recv_cancel,
        .iface_tag_sched_enable   = uct_bxi_iface_tag_sched_enable,
        .iface_tag_sched_disable  = uct_bxi_iface_tag_sched_disable,
        .iface_tag_sched_recv     = uct_bxi_iface_tag_sched_recv,
        .iface_tag_sched_send     = uct_bxi_iface_tag_sched_send,
        .iface_tag_sched_release  = uct_bxi_iface_tag_sched_release,
};

static uct_bxi_iface_ops_t uct_bxi_iface_ops = {
        .super =
                {
                        .iface_estimate_perf = uct_base_iface_estimate_perf,
                        .iface_vfs_refresh   = (uct_iface_vfs_refresh_func_t)
                                ucs_empty_function_return_unsupported,
                        .ep_query = (uct_ep_query_func_t)
                                ucs_empty_function_return_unsupported,
                        .ep_invalidate = (uct_ep_invalidate_func_t)
                                ucs_empty_function_return_unsupported,
                        .ep_connect_to_ep_v2 =
                                ucs_empty_function_return_unsupported,
                        .iface_is_reachable_v2 =
                                *(uct_iface_is_reachable_v2_func_t)
                                        ucs_empty_function_return_unsupported,
                        .ep_is_connected = uct_bxi_ep_is_connected,
                },
};

UCS_CLASS_DEFINE(uct_bxi_iface_t, uct_base_iface_t);
static UCS_CLASS_DEFINE_NEW_FUNC(uct_bxi_iface_t, uct_iface_t, uct_md_h,
                                 uct_worker_h, const uct_iface_params_t *,
                                 const uct_iface_config_t *);
static UCS_CLASS_DEFINE_DELETE_FUNC(uct_bxi_iface_t, uct_iface_t);

UCT_TL_DEFINE_ENTRY(&uct_bxi_component, bxi, uct_bxi_iface_query_tl_devices,
                    uct_bxi_iface_t, UCT_BXI_CONFIG_PREFIX,
                    uct_bxi_iface_config_table, uct_bxi_iface_config_t);

UCT_SINGLE_TL_INIT(&uct_bxi_component, bxi, ctor, PtlInit(), PtlFini())
