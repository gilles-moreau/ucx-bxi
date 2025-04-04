#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "bxi.h"
#include "bxi_ep.h"
#include "bxi_iface.h"

#include <ucs/sys/math.h>

#define UCT_PTL_IFACE_OVERHEAD 10e-8
#define UCT_PTL_IFACE_LATENCY  ucs_linear_func_make(80e-8, 0)

static uct_iface_ops_t     uct_bxi_iface_tl_ops;
static uct_bxi_iface_ops_t uct_bxi_iface_ops;
/* Forward function declaration. */
static ucs_status_t uct_bxi_iface_get_rxq(uct_bxi_iface_t *iface,
                                          ptl_pt_index_t   pti,
                                          uct_bxi_rxq_t  **rxq_p);
static ucs_status_t uct_bxi_iface_get_ep(uct_bxi_iface_t *iface,
                                         ptl_process_t    pid,
                                         uct_bxi_ep_t   **ep_p);

char *uct_bxi_event_str[] = {
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
        {"", "ALLOC=heap", NULL, ucs_offsetof(uct_bxi_iface_config_t, super),
         UCS_CONFIG_TYPE_TABLE(uct_iface_config_table)},

        {"MAX_TX_QUEUE_LEN", "256",
         "Maximum number of outstanding operations (default: 256).",
         ucs_offsetof(uct_bxi_iface_config_t, tx.max_queue_len),
         UCS_CONFIG_TYPE_UINT},

        UCT_IFACE_MPOOL_CONFIG_FIELDS(
                "TX_", -1, 32, 128m, 1.0, "send",
                ucs_offsetof(uct_bxi_iface_config_t, tx.mp), "\n"),

        {"MAX_RX_QUEUE_LEN", "256",
         "Maximum number of receive posted (default: 256).",
         ucs_offsetof(uct_bxi_iface_config_t, rx.max_queue_len),
         UCS_CONFIG_TYPE_UINT},

        UCT_IFACE_MPOOL_CONFIG_FIELDS(
                "RX_AM_", -1, 32, 128m, 1.0, "recv_am",
                ucs_offsetof(uct_bxi_iface_config_t, rx.am_mp), "\n"),

        {"SEG_SIZE", "8192",
         "Size of bounce buffers used for post_send "
         "and post_recv. (default: 8192).",
         ucs_offsetof(uct_bxi_iface_config_t, seg_size),
         UCS_CONFIG_TYPE_MEMUNITS},

        {"MAX_EP_RETRIES", "16",
         "Maximum number of send retry on a given endpoint (default: 16).",
         ucs_offsetof(uct_bxi_iface_config_t, max_ep_retries),
         UCS_CONFIG_TYPE_UINT},

        {"TM_ENABLE", "n", "Enable HW tag matching",
         ucs_offsetof(uct_bxi_iface_config_t, tm.enable), UCS_CONFIG_TYPE_BOOL},

        UCT_IFACE_MPOOL_CONFIG_FIELDS(
                "RX_TAG_", -1, 32, 128m, 1.0, "recv_tag",
                ucs_offsetof(uct_bxi_iface_config_t, rx.tag_mp),
                "Memory pool of bounced buffers posted in the Portals overflow "
                "list.\n"),

        {"MAX_TM_OP_CTX", "256",
         "Maximum number of tag matching operation contexts (default: 256).",
         ucs_offsetof(uct_bxi_iface_config_t, tm.max_op_ctx),
         UCS_CONFIG_TYPE_UINT},

        UCT_IFACE_MPOOL_CONFIG_FIELDS(
                "TM_OP_CTX_", -1, 32, 128m, 1.0, "tm_op_ctx",
                ucs_offsetof(uct_bxi_iface_config_t, tm.op_ctx_mp), "\n"),

        {"TM_LIST_SIZE", "4",
         "Limits the number of tags posted to the HW for matching. The actual "
         "limit is a minimum between this value and the maximum value "
         "supported by the HW. \n -1 means no limit.",
         ucs_offsetof(uct_bxi_iface_config_t, tm.list_size),
         UCS_CONFIG_TYPE_UINT},

        {"MAX_OPERATION_CONTEXT", "32",
         "Number of operation context allocable (default: 32)",
         ucs_offsetof(uct_bxi_iface_config_t, tm.max_op_ctx),
         UCS_CONFIG_TYPE_UINT},

        {NULL},
};

static UCS_F_ALWAYS_INLINE void
uct_bxi_iface_mem_desc_completion_op(uct_bxi_iface_send_op_t *op)
{
  ucs_assert(op->flags & UCT_BXI_IFACE_SEND_OP_FLAG_INUSE);
  op->flags &= ~UCT_BXI_IFACE_SEND_OP_FLAG_INUSE;
  op->handler(op, NULL);
}

static ucs_status_t uct_bxi_iface_handle_am_events(uct_bxi_iface_t *iface,
                                                   ptl_event_t     *ev)
{
  ucs_status_t          status = UCS_OK;
  uint8_t               am_id  = UCT_BXI_HDR_GET_AM_ID(ev->match_bits);
  uct_bxi_recv_block_t *block  = (uct_bxi_recv_block_t *)ev->user_ptr;

  switch (ev->type) {
  case PTL_EVENT_PUT:
    status = uct_iface_invoke_am(&iface->super, am_id, ev->start, ev->mlength,
                                 0);

    uct_bxi_iface_trace_am(iface, UCT_AM_TRACE_TYPE_RECV, am_id, ev->start,
                           ev->mlength);
    break;
  case PTL_EVENT_AUTO_UNLINK:
    /* One block has been unlinked since it is full. All received data has 
       * been processed at that point. */
    status = uct_bxi_recv_block_activate(block, NULL);
    break;
  case PTL_EVENT_PUT_OVERFLOW:
  case PTL_EVENT_LINK:
  case PTL_EVENT_GET_OVERFLOW:
  case PTL_EVENT_GET:
  case PTL_EVENT_AUTO_FREE:
  case PTL_EVENT_ATOMIC:
  case PTL_EVENT_FETCH_ATOMIC:
  case PTL_EVENT_SEARCH:
  case PTL_EVENT_SEND:
  case PTL_EVENT_REPLY:
  case PTL_EVENT_FETCH_ATOMIC_OVERFLOW:
  case PTL_EVENT_ATOMIC_OVERFLOW:
  case PTL_EVENT_ACK:
    ucs_error("BXI: event %s should not have been triggered",
              uct_bxi_event_str[ev->type]);
    status = UCS_ERR_IO_ERROR;
    break;
  case PTL_EVENT_PT_DISABLED:
    ucs_error("BXI: event %s. RX Control flow not implemented.",
              uct_bxi_event_str[ev->type]);
    status = UCS_OK;
    break;
  default:
    break;
  }

  return status;
}

static UCS_F_ALWAYS_INLINE int
uct_bxi_iface_is_unexpected(uct_bxi_recv_block_t *block)
{
  return block->list != PTL_OVERFLOW_LIST;
}

static ucs_status_t uct_bxi_iface_handle_tag_events(uct_bxi_iface_t *iface,
                                                    ptl_event_t     *ev)
{
  ucs_status_t          status = UCS_OK;
  uct_bxi_hdr_rndv_t   *hdr;
  uct_bxi_ep_t         *reply_ep;
  uct_bxi_recv_block_t *block = (uct_bxi_recv_block_t *)ev->user_ptr;

  ucs_debug("BXI: event. type=%s, size=%lu, start=%p, pti=%d",
            uct_bxi_event_str[ev->type], ev->mlength, ev->start, ev->pt_index);

  // TODO: check for truncated messages
  switch (ev->type) {
  case PTL_EVENT_PUT:
    if (uct_bxi_iface_is_unexpected(block)) {
      if (uct_bxi_iface_is_rndv(ev->hdr_data)) {
        /* In this case, the protocol will always be continued by UCP. */
        switch (ev->hdr_data & 0xful) {
        case UCT_BXI_TAG_PROT_RNDV_HW:
          hdr    = ev->start;
          status = iface->tm.rndv_unexp.cb(
                  iface->tm.rndv_unexp.arg, 0, ev->match_bits,
                  (const void *)(hdr + 1), hdr->header_length, hdr->remote_addr,
                  hdr->length, NULL);
          break;
        case UCT_BXI_TAG_PROT_RNDV_SW:
          status = iface->tm.rndv_unexp.cb(
                  iface->tm.rndv_unexp.arg, 0, ev->match_bits,
                  (const void *)ev->start, ev->mlength, 0, 0, NULL);
          break;
        default:
          ucs_fatal("BXI: unrecognized rndv protocol.");
          break;
        }
      } else {
        status = iface->tm.eager_unexp.cb(iface->tm.eager_unexp.arg, ev->start,
                                          ev->mlength, UCT_CB_PARAM_FLAG_FIRST,
                                          ev->match_bits, ev->hdr_data, NULL);
      }
    } else {
      /* Receive block has been consumed, notify UCP layer so it can remove 
       * the tag from its expected queues. Buffer may also be removed from 
       * hash table. */
      block->ctx->tag_consumed_cb(block->ctx);
      uct_bxi_iface_tag_del_from_hash(iface, block->start);

      /* Now, perform protocol specific actions. */
      if (uct_bxi_iface_is_rndv(ev->hdr_data)) {
        switch (ev->hdr_data & 0xful) {
        case UCT_BXI_TAG_PROT_RNDV_HW:
          hdr = ev->start;

          /* First, get the initiator endpoint. */
          uct_bxi_iface_get_ep(iface, ev->initiator, &reply_ep);

          /* No not forget to overwrite block size with initiator data: sender size
           * may differ from receiver size! */
          block->size = hdr->length;

          /* Then, perform the GET operation. Add to pending queue if no resource 
           * are available. */
          status = uct_bxi_ep_tag_rndv_zcopy_get(
                  reply_ep, UCT_BXI_HDR_GET_MATCH(ev->hdr_data), block);
          if (status == UCS_ERR_NO_RESOURCE) {
            status = uct_bxi_ep_pending_get_add(
                    reply_ep, UCT_BXI_HDR_GET_MATCH(ev->hdr_data), block);
            ucs_assert_always(status == UCS_OK);
          }

          /* Receive block may not be release since completion callback from tag 
           * context will be called on GET completion. */
          break;
        case UCT_BXI_TAG_PROT_RNDV_SW:
          /* UCP will proceed with a normal software rendez-vous protocol. */
          block->ctx->rndv_cb(block->ctx, ev->match_bits, ev->start,
                              ev->mlength, UCS_OK, 0);
          break;
        default:
          ucs_fatal("BXI: unrecognized rndv protocol.");
          break;
        }
      } else {
        /* Eager expected message completion. */
        block->ctx->completed_cb(block->ctx, ev->match_bits, ev->hdr_data,
                                 ev->mlength, NULL, UCS_OK);
      }

      /* At this point, receive block may safely be released back to the memory 
       * pool. */
      ucs_mpool_put(&block->elem);
    }
    break;
  case PTL_EVENT_GET:
    uct_bxi_iface_mem_desc_completion_op(block->op);
    break;
  case PTL_EVENT_PT_DISABLED:
    ucs_error("PTL: event %s. Control flow not implemented.",
              uct_bxi_event_str[ev->type]);
    status = UCS_ERR_IO_ERROR;
    goto err;
    break;
  case PTL_EVENT_AUTO_UNLINK:
    /* A receive block from the PTL_OVERFLOW_LIST has been filled. 
     * Link it back, all included data has been processed already. */
    status = uct_bxi_recv_block_activate(block, NULL);
    break;
  case PTL_EVENT_ACK:
  case PTL_EVENT_REPLY:
  case PTL_EVENT_PUT_OVERFLOW:
  case PTL_EVENT_GET_OVERFLOW:
  case PTL_EVENT_AUTO_FREE:
  case PTL_EVENT_ATOMIC:
  case PTL_EVENT_FETCH_ATOMIC:
  case PTL_EVENT_FETCH_ATOMIC_OVERFLOW:
  case PTL_EVENT_ATOMIC_OVERFLOW:
  case PTL_EVENT_LINK:
  case PTL_EVENT_SEARCH:
  case PTL_EVENT_SEND:
    ucs_error("PTL: event %s should not have been triggered",
              uct_bxi_event_str[ev->type]);
    status = UCS_ERR_IO_ERROR;
    break;
  default:
    break;
  }

err:
  return status;
}

ucs_status_t uct_bxi_iface_query(uct_iface_h uct_iface, uct_iface_attr_t *attr)
{
  uct_bxi_iface_t *iface = ucs_derived_of(uct_iface, uct_bxi_iface_t);

  uct_base_iface_query(&iface->super, attr);

  attr->cap.am.max_short = iface->config.max_inline - sizeof(uint64_t);
  attr->cap.am.max_bcopy = iface->config.seg_size;
  attr->cap.am.max_zcopy = 0;
  attr->cap.am.max_iov   = iface->config.max_iovecs;

  attr->cap.tag.recv.min_recv   = 0;
  attr->cap.tag.eager.max_short = iface->config.max_inline;
  attr->cap.tag.eager.max_bcopy = iface->config.seg_size;
  attr->cap.tag.eager.max_zcopy = iface->config.max_msg_size;
  attr->cap.tag.eager.max_iov   = iface->config.max_iovecs;
  attr->cap.tag.rndv.max_hdr    = 128;
  attr->cap.tag.rndv.max_iov    = 1;
  attr->cap.tag.rndv.max_zcopy  = iface->config.max_msg_size;

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

  attr->cap.flags = UCT_IFACE_FLAG_AM_BCOPY | UCT_IFACE_FLAG_PUT_BCOPY |
                    UCT_IFACE_FLAG_GET_BCOPY | UCT_IFACE_FLAG_PUT_SHORT |
                    UCT_IFACE_FLAG_PUT_ZCOPY | UCT_IFACE_FLAG_GET_ZCOPY |
                    UCT_IFACE_FLAG_PENDING | UCT_IFACE_FLAG_CB_SYNC |
                    UCT_IFACE_FLAG_INTER_NODE |
                    UCT_IFACE_FLAG_CONNECT_TO_IFACE | UCT_IFACE_FLAG_EP_CHECK;

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
  attr->cap.flags |= UCT_IFACE_FLAG_ATOMIC_CPU;

  attr->latency             = UCT_PTL_IFACE_LATENCY;
  attr->bandwidth.dedicated = 8192 * UCS_MBYTE;
  attr->bandwidth.shared    = 0;
  attr->overhead            = UCT_PTL_IFACE_OVERHEAD;
  attr->priority            = 1;

  return UCS_OK;
}

static ucs_status_t uct_bxi_iface_get_addr(uct_iface_h       tl_iface,
                                           uct_iface_addr_t *tl_addr)
{
  uct_bxi_iface_addr_t *addr  = (void *)tl_addr;
  uct_bxi_iface_t      *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);

  addr->rma = iface->rx.rma.pti;
  addr->am  = uct_bxi_rxq_get_addr(iface->rx.am.queue);
  addr->tag = uct_bxi_rxq_get_addr(iface->rx.tag.queue);

  return UCS_OK;
}

ucs_status_t uct_bxi_iface_get_device_address(uct_iface_h        tl_iface,
                                              uct_device_addr_t *tl_addr)
{
  uct_bxi_device_addr_t *addr  = (void *)tl_addr;
  uct_bxi_iface_t       *iface = ucs_derived_of(tl_iface, uct_bxi_iface_t);

  addr->pid = iface->md->pid;

  return UCS_OK;
}

static unsigned uct_bxi_iface_poll_rx(uct_bxi_iface_t *iface)
{
  unsigned       progressed = 0;
  ptl_event_t    ev;
  int            ret;
  uct_bxi_rxq_t *rxq;

  while (1) {
    ret = PtlEQGet(iface->rx.eqh, &ev);

    switch (ret) {
    case PTL_OK:
      /* Get RX Queue from Portals Table Index */
      uct_bxi_iface_get_rxq(iface, ev.pt_index, &rxq);

      /* Handle the event. */
      progressed += rxq->handler(iface, &ev);
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
  return progressed;
}

static ucs_status_t uct_bxi_iface_handle_tx_err(uct_bxi_iface_t    *iface,
                                                uct_bxi_mem_desc_t *mem_desc,
                                                ptl_ct_event_t      failures)
{
  int                      i;
  ucs_status_t             status = UCS_OK;
  uct_bxi_iface_send_op_t *op;
  ptl_event_t              ev;

  for (i = 0; i < failures.failure; i++) {
    status = uct_bxi_wrap(PtlEQGet(iface->tx.err_eqh, &ev));
    if (status != UCS_OK)
      break;

    ucs_assert(ev.type == PTL_EVENT_PT_DISABLED);
    op = (uct_bxi_iface_send_op_t *)ev.user_ptr;
    ucs_error("BXI: operation failed. op=%p, sn=%lu, mem desc=%p", op, op->sn,
              mem_desc);

    /* Remove operation from queue. */
    ucs_queue_remove(&mem_desc->send_ops, &op->elem);

    /* Close endpoint. */
    op->ep->conn_state = UCT_BXI_EP_CONN_CLOSED;

    status = uct_iface_handle_ep_err(&iface->super.super, &op->ep->super.super,
                                     UCS_ERR_ENDPOINT_TIMEOUT);

    ucs_assert(status == UCS_OK);
  }

  /* Error has been handled, reset counter. */
  status = uct_bxi_wrap(PtlCTInc(
          mem_desc->cth, (ptl_ct_event_t){.success = failures.failure,
                                          .failure = -failures.failure}));

  return status;
}

unsigned uct_bxi_iface_poll_tx(uct_bxi_iface_t    *iface,
                               uct_bxi_mem_desc_t *mem_desc)
{
  ucs_status_t             status     = UCS_OK;
  unsigned                 progressed = 0;
  uct_bxi_iface_send_op_t *op;
  ptl_ct_event_t           ct_count;

  /* Do not poll count if there are no outstanding operations. */
  if (ucs_queue_is_empty(&mem_desc->send_ops)) {
    return 0;
  }

  status = uct_bxi_wrap(PtlCTGet(mem_desc->cth, &ct_count));
  if (status != UCS_OK) {
    ucs_error("BXI: error polling counter.");
    goto err;
  }

  if (ct_count.failure > 0) {
    status = uct_bxi_iface_handle_tx_err(iface, mem_desc, ct_count);
    if (status != UCS_OK) {
      ucs_error("BXI: error handling error.");
      goto err;
    }
  }

  /* Loop on all outstanding operation and compare their sequence number 
   * with the current value of the completion counter. */
  ucs_queue_for_each_extract (
          op, &mem_desc->send_ops, elem,
          UCS_CIRCULAR_COMPARE64(ct_count.success, >, op->sn)) {
    uct_bxi_iface_mem_desc_completion_op(op);

    progressed++;
  }

err:
  return progressed;
}

unsigned uct_bxi_iface_progress(uct_iface_t *super)
{
  unsigned         count = 0;
  uct_bxi_iface_t *iface = ucs_derived_of(super, uct_bxi_iface_t);

  count = uct_bxi_iface_poll_rx(iface);
  if (!uct_bxi_iface_should_poll_tx(count)) {
    return count;
  }

  count = uct_bxi_iface_poll_tx(iface, iface->tx.mem_desc);
  return count;
}

ucs_status_t uct_bxi_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                 uct_completion_t *comp)
{
  return UCS_OK;
}

ucs_status_t uct_bxi_iface_fence(uct_iface_h tl_iface, unsigned flags)
{
  return UCS_OK;
}

ucs_status_t
uct_bxi_iface_query_tl_devices(uct_md_h                   uct_md,
                               uct_tl_device_resource_t **tl_devices_p,
                               unsigned                  *num_tl_devices_p)
{
  uct_bxi_md_t *md = ucs_derived_of(uct_md, uct_bxi_md_t);
  return uct_single_device_resource(uct_md, md->device, UCT_DEVICE_TYPE_NET,
                                    UCS_SYS_DEVICE_ID_UNKNOWN, tl_devices_p,
                                    num_tl_devices_p);
}

ucs_status_t uct_bxi_iface_add_ep(uct_bxi_iface_t *iface, uct_bxi_ep_t *ep)
{
  int      ret;
  khiter_t iter;
  uint64_t pid = 0;

  /* Transform Portals pid to uint64_t. */
  pid  = ep->dev_addr.pid.phys.nid;
  pid  = pid << 32;
  pid |= ep->dev_addr.pid.phys.pid;

  /* Enable event handling. It is retrieved on event polling
  * using the Portals Table Index. */
  iter = kh_put(uct_bxi_eps, &iface->eps, pid, &ret);
  ucs_assertv((ret != UCS_KH_PUT_FAILED) && (ret != UCS_KH_PUT_KEY_PRESENT),
              "ret %d", ret);
  kh_value(&iface->eps, iter) = ep;

  return UCS_OK;
}

static ucs_status_t uct_bxi_iface_get_ep(uct_bxi_iface_t *iface,
                                         ptl_process_t    ptl_pid,
                                         uct_bxi_ep_t   **ep_p)
{
  khiter_t iter;
  uint64_t pid;

  /* Transform Portals pid to uint64_t. */
  pid  = ptl_pid.phys.nid;
  pid  = pid << 32;
  pid |= ptl_pid.phys.pid;

  /* Get the UCT endpoint. */
  iter = kh_get(uct_bxi_eps, &iface->eps, pid);
  if (iter == kh_end(&iface->eps)) {
    ucs_fatal("BXI: endpoint not found. nid=%d, pid=%d", ptl_pid.phys.nid,
              ptl_pid.phys.pid);
  }
  *ep_p = kh_val(&iface->eps, iter);

  return UCS_OK;
}

static ucs_status_t uct_bxi_iface_add_rxq(uct_bxi_iface_t *iface,
                                          uct_bxi_rxq_t   *rxq)
{
  int            ret;
  khiter_t       iter;
  ptl_pt_index_t pti = uct_bxi_rxq_get_addr(rxq);

  /* Enable event handling. It is retrieved on event polling
  * using the Portals Table Index. */
  iter = kh_put(uct_bxi_rxq, &iface->rx.queues, pti, &ret);
  ucs_assertv((ret != UCS_KH_PUT_FAILED) && (ret != UCS_KH_PUT_KEY_PRESENT),
              "ret %d", ret);
  kh_value(&iface->rx.queues, iter) = rxq;

  return UCS_OK;
}

static ucs_status_t uct_bxi_iface_get_rxq(uct_bxi_iface_t *iface,
                                          ptl_pt_index_t   pti,
                                          uct_bxi_rxq_t  **rxq_p)
{
  khiter_t iter;

  iter = kh_get(uct_bxi_rxq, &iface->rx.queues, pti);
  if (iter == kh_end(&iface->rx.queues)) {
    ucs_fatal("BXI: unknown Portals Table Index. pti=%d", pti);
  }
  *rxq_p = kh_val(&iface->rx.queues, iter);

  return UCS_OK;
}

void uct_bxi_iface_recv_block_init(ucs_mpool_t *mp, void *obj, void *chunk)
{
  uct_bxi_iface_t *iface =
          ucs_container_of(mp, uct_bxi_iface_t, tm.recv_block_mp);
  uct_bxi_recv_block_t *block = obj;

  block->rxq = iface->rx.tag.queue;
}

static ucs_mpool_ops_t uct_bxi_recv_block_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = uct_bxi_iface_recv_block_init,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

//NOTE: Think of preallocating all the counters associated with the
//      operation contexts during memory pool initialization.
static ucs_mpool_ops_t uct_bxi_op_ctx_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = NULL,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

static ucs_status_t uct_bxi_iface_tag_init(uct_bxi_iface_t              *iface,
                                           const uct_iface_params_t     *params,
                                           const uct_bxi_iface_config_t *config)
{
  ucs_status_t        status = UCS_OK;
  ucs_mpool_params_t  mp_param;
  uct_bxi_rxq_param_t rxq_param;

  iface->tm.enabled = config->tm.enable;

  if (!iface->tm.enabled) {
    goto out;
  }

  iface->config.tm.max_tags   = config->tm.list_size;
  iface->config.tm.max_op_ctx = config->tm.max_op_ctx;

  iface->tm.eager_unexp.cb = params->eager_cb;
  iface->tm.rndv_unexp.cb  = params->rndv_cb;
  iface->tm.eager_unexp.arg =
          UCT_IFACE_PARAM_VALUE(params, eager_arg, HW_TM_EAGER_ARG, NULL);
  iface->tm.rndv_unexp.arg =
          UCT_IFACE_PARAM_VALUE(params, rndv_arg, HW_TM_RNDV_ARG, NULL);
  iface->tm.recv_tried_offload = 0;

  kh_init_inplace(uct_bxi_tag_addrs, &iface->tm.tag_addrs);

  rxq_param = (uct_bxi_rxq_param_t){
          .eqh     = iface->rx.eqh,
          .nih     = iface->md->nih,
          .mp      = config->rx.tag_mp,
          .list    = PTL_OVERFLOW_LIST,
          .name    = "rxq-tag",
          .handler = uct_bxi_iface_handle_tag_events,
  };
  status = uct_bxi_rxq_create(iface, &rxq_param, &iface->rx.tag.queue);
  if (status != UCS_OK) {
    goto out;
  }

  /* Append RXQ to the hash table for event handling. */
  uct_bxi_iface_add_rxq(iface, iface->rx.tag.queue);

  /* Work pool of operation. */
  ucs_mpool_params_reset(&mp_param);
  mp_param = (ucs_mpool_params_t){
          .max_chunk_size =
                  iface->config.tm.max_tags * sizeof(uct_bxi_recv_block_t),
          .elems_per_chunk = iface->config.tm.max_tags,
          .max_elems       = iface->config.tm.max_tags,
          .elem_size       = sizeof(uct_bxi_recv_block_t),
          .alignment       = UCS_SYS_CACHE_LINE_SIZE,
          .ops             = &uct_bxi_recv_block_mpool_ops,
          .name            = "tag-recv-block",
          .grow_factor     = 1,
  };
  status = ucs_mpool_init(&mp_param, &iface->tm.recv_block_mp);
  if (status != UCS_OK) {
    goto err_release_rxq;
  }

  ucs_mpool_params_reset(&mp_param);
  mp_param = (ucs_mpool_params_t){
          .max_chunk_size  = config->tm.op_ctx_mp.max_chunk_size,
          .elems_per_chunk = config->tm.op_ctx_mp.bufs_grow,
          .max_elems       = config->tm.max_op_ctx,
          .elem_size       = sizeof(uct_bxi_op_ctx_t),
          .alignment       = UCS_SYS_CACHE_LINE_SIZE,
          .ops             = &uct_bxi_op_ctx_mpool_ops,
          .name            = "tag-op-ctx",
          .grow_factor     = 1,
  };
  status = ucs_mpool_init(&mp_param, &iface->tm.op_ctx_mp);
  if (status != UCS_OK) {
    goto err_release_blockrecvmp;
  }

  return status;

err_release_blockrecvmp:
  ucs_mpool_cleanup(&iface->tm.recv_block_mp, 0);
err_release_rxq:
  uct_bxi_rxq_fini(iface->rx.tag.queue);
out:
  return status;
}

static void uct_bxi_iface_tag_fini(uct_bxi_iface_t *iface)
{
  void *recv_buffer;

  if (!iface->tm.enabled) {
    goto out;
  }

  kh_foreach_key (&iface->tm.tag_addrs, recv_buffer, {
    ucs_debug("destroying iface %p, with recv buffer %p offloaded to the HW",
              iface, recv_buffer);
  })
    ;
  kh_destroy_inplace(uct_bxi_tag_addrs, &iface->tm.tag_addrs);

  /* Release TAG RX queue. */
  uct_bxi_rxq_fini(iface->rx.tag.queue);

  /* And receive block memory pool.*/
  ucs_mpool_cleanup(&iface->tm.recv_block_mp, 1);

out:
  return;
}

static inline void
uct_bxi_iface_config_init(uct_bxi_iface_t              *iface,
                          const uct_bxi_iface_config_t *config)
{
  iface->config.seg_size         = config->seg_size;
  iface->config.tx.max_queue_len = config->tx.max_queue_len;
  iface->config.rx.max_queue_len = config->rx.max_queue_len;

  iface->config.max_iovecs   = ucs_min(iface->md->config.limits.max_iovecs, 1);
  iface->config.max_msg_size = iface->md->config.limits.max_msg_size;
  iface->config.max_inline = ucs_min(iface->md->config.limits.max_volatile_size,
                                     UCS_ALLOCA_MAX_SIZE);
  iface->config.device_addr_size = sizeof(uct_bxi_device_addr_t);
  iface->config.iface_addr_size  = sizeof(uct_bxi_iface_addr_t);
  iface->config.ep_addr_size     = sizeof(uct_bxi_ep_addr_t);
}

void uct_bxi_iface_send_init(ucs_mpool_t *mp, void *obj, void *chunk)
{
  uct_bxi_iface_t *iface =
          ucs_container_of(mp, uct_bxi_iface_t, tx.send_desc_mp);
  uct_bxi_iface_send_op_t *op = obj;

  op->mem_desc = iface->tx.mem_desc;
}

static ucs_mpool_ops_t uct_bxi_send_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = uct_bxi_iface_send_init,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

static ucs_mpool_ops_t uct_bxi_send_flush_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = NULL,
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
  mp_params = (ucs_mpool_params_t){
          .max_chunk_size = config->tx.mp.max_chunk_size *
                            sizeof(uct_bxi_iface_send_op_t),
          .elems_per_chunk = config->tx.mp.bufs_grow,
          .max_elems       = config->tx.mp.max_bufs,
          .elem_size       = sizeof(uct_bxi_iface_send_op_t),
          .alignment       = UCS_SYS_CACHE_LINE_SIZE,
          .ops             = &uct_bxi_send_mpool_ops,
          .name            = "send-comp-ops",
          .grow_factor     = config->tx.mp.grow_factor,
  };
  status = ucs_mpool_init(&mp_params, &iface->tx.send_op_mp);

  if (status != UCS_OK) {
    goto err;
  }

  /* Allocate memory of flush operations. */
  ucs_mpool_params_reset(&mp_params);
  mp_params = (ucs_mpool_params_t){
          .elems_per_chunk = 256,
          .max_elems       = 256,
          .elem_size       = sizeof(uct_bxi_iface_send_op_t),
          .alignment       = UCS_SYS_CACHE_LINE_SIZE,
          .ops             = &uct_bxi_send_flush_mpool_ops,
          .name            = "bxi-flush-ops",
  };
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
  uct_bxi_md_t           *md     = ucs_derived_of(tl_md, uct_bxi_md_t);
  uct_bxi_iface_config_t *config =
          ucs_derived_of(uct_config, uct_bxi_iface_config_t);
  uct_bxi_mem_desc_param_t mem_desc_param;
  ucs_mpool_params_t       mp_params;
  uct_bxi_rxq_param_t      rxq_param;
  ptl_me_t                 me;

  UCS_CLASS_CALL_SUPER_INIT(
          uct_base_iface_t, &uct_bxi_iface_tl_ops, &uct_bxi_iface_ops.super,
          tl_md, worker, params,
          &config->super UCS_STATS_ARG(
                  ((params->field_mask & UCT_IFACE_PARAM_FIELD_STATS_ROOT) &&
                   (params->stats_root != NULL)) ?
                          params->stats_root :
                          dev->stats)
                   UCS_STATS_ARG(params->mode.device.dev_name));

  /* Initialize all config entries. */
  uct_bxi_iface_config_init(self, config);

  /* Create Event Queue used for RX events. */
  status = uct_bxi_wrap(
          PtlEQAlloc(md->nih, self->config.max_events, &self->rx.eqh));
  if (status != UCS_OK) {
    goto err;
  }

  /* Create RX Queues for AM messages. Block are posted to the Priority List */
  rxq_param = (uct_bxi_rxq_param_t){
          .eqh     = self->rx.eqh,
          .nih     = self->md->nih,
          .mp      = config->rx.am_mp,
          .list    = PTL_PRIORITY_LIST,
          .handler = uct_bxi_iface_handle_am_events,
          .name    = "rxq-am",
  };
  status = uct_bxi_rxq_create(self, &rxq_param, &self->rx.am.queue);
  if (status != UCS_OK) {
    goto err_clean_rxevq;
  }

  /* Append RXQ to the hash table for event handling. */
  uct_bxi_iface_add_rxq(self, self->rx.am.queue);

  /* Initialize TAG resources if enabled. */
  status = uct_bxi_iface_tag_init(self, params, config);
  if (status != UCS_OK) {
    goto err_clean_rxq;
  }

  /* Create TX Event Queue that will be used for error handling. */
  //FIXME: maybe set a lower number of events for the error queue.
  status = uct_bxi_wrap(
          PtlEQAlloc(md->nih, self->config.max_events, &self->tx.err_eqh));
  if (status != UCS_OK) {
    goto err_clean_tag;
  }

  /* Before setting TX operations, create the Memory Descriptor that
   * spans the whole virtual memory range. */
  mem_desc_param = (uct_bxi_mem_desc_param_t){
          .eqh     = self->tx.err_eqh,
          .start   = NULL,
          .length  = PTL_SIZE_MAX,
          .options = PTL_CT_ACK_REQ,
          .flags   = UCT_BXI_MEM_DESC_FLAG_ALLOCATE,
  };
  status = uct_bxi_md_mem_desc_create(md, &mem_desc_param, &self->tx.mem_desc);
  if (status != UCS_OK) {
    goto err_clean_errevq;
  }

  /* Create TX buffers mempool */
  ucs_mpool_params_reset(&mp_params);
  mp_params = (ucs_mpool_params_t){
          .max_chunk_size  = config->tx.mp.max_chunk_size,
          .elems_per_chunk = config->tx.mp.bufs_grow,
          .elem_size = sizeof(uct_bxi_iface_send_op_t) + self->config.seg_size,
          .max_elems = config->tx.mp.max_bufs,
          .alignment = UCS_SYS_CACHE_LINE_SIZE,
          .ops       = &uct_bxi_send_mpool_ops,
          .name      = "send-desc-mp",
          .grow_factor = config->tx.mp.grow_factor,
  };
  status = ucs_mpool_init(&mp_params, &self->tx.send_desc_mp);
  if (status != UCS_OK) {
    goto err_clean_mem_desc;
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

  /* Initialize Portals Table Entry for RDMA operations. */
  status = uct_bxi_wrap(PtlPTAlloc(md->nih, PTL_PT_FLOWCTRL, self->rx.eqh,
                                   PTL_PT_ANY, &self->rx.rma.pti));
  if (status != UCS_OK) {
    goto err_clean_pending;
  }

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
  status = uct_ptl_wrap(PtlMEAppend(md->nih, self->rx.rma.pti, &me,
                                    PTL_PRIORITY_LIST, NULL,
                                    &self->rx.rma.entry.meh));
  if (status != UCS_OK) {
    goto err_clean_rmapti;
  }

  /* PTL hdr is used within internal protocols and 64 bits are needed. Endpoint 
   * hash table uses ptl_process_t supposing it is 8 bytes. */
  ucs_assert(sizeof(uint64_t) <= sizeof(ptl_hdr_data_t));
  ucs_assert(sizeof(uint64_t) <= sizeof(ptl_process_t));

  return status;

err_clean_rmapti:
  PtlPTFree(md->nih, self->rx.rma.pti);
err_clean_pending:
  ucs_mpool_cleanup(&self->tx.pending_mp, 0);
err_clean_txops:
  uct_bxi_iface_tx_ops_fini(self);
err_clean_txbuffer:
  ucs_mpool_cleanup(&self->tx.send_desc_mp, 1);
err_clean_mem_desc:
  uct_bxi_md_mem_desc_fini(self->tx.mem_desc);
err_clean_errevq:
  uct_bxi_wrap(PtlEQFree(self->tx.err_eqh));
err_clean_tag:
  uct_bxi_iface_tag_fini(self);
err_clean_rxq:
  uct_bxi_rxq_fini(self->rx.am.queue);
err_clean_rxevq:
  uct_bxi_wrap(PtlEQFree(self->rx.eqh));
err:
  return status;
}

static UCS_CLASS_CLEANUP_FUNC(uct_bxi_iface_t)
{
  /* Clean RDMA resources. */
  PtlMEUnlink(self->rx.rma.entry.meh);
  PtlPTFree(self->md->nih, self->rx.rma.pti);

  /* Clean TX resources. */
  ucs_mpool_cleanup(&self->tx.pending_mp, 1);
  uct_bxi_iface_tx_ops_fini(self);
  ucs_mpool_cleanup(&self->tx.send_desc_mp, 1);
  uct_bxi_md_mem_desc_fini(self->tx.mem_desc);
  PtlEQFree(self->tx.err_eqh);

  /* Clean RX resources */
  /* Clean TAG resources if enabled. */
  uct_bxi_iface_tag_fini(self);

  /* Clean AM resources */
  uct_bxi_rxq_fini(self->rx.am.queue);
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
        .ep_tag_eager_short       = ucs_empty_function_return_unsupported,
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
        .iface_tag_recv_overflow  = uct_bxi_iface_tag_recv_overflow,
        .iface_tag_create_oop     = uct_bxi_iface_tag_create_op_ctx,
        .iface_tag_delete_oop     = uct_bxi_iface_tag_delete_op_ctx,
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
