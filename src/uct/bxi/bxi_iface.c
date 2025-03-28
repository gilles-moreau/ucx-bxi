#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "bxi.h"
#include "bxi_ep.h"
#include "bxi_iface.h"

#include <ucs/sys/math.h>

#define UCT_PTL_IFACE_OVERHEAD 10e-8
#define UCT_PTL_IFACE_LATENCY  ucs_linear_func_make(80e-8, 0)

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
                ucs_offsetof(uct_bxi_iface_config_t, rx.tag_mp), "\n"),

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

ucs_status_t uct_bxi_iface_query(uct_iface_h uct_iface, uct_iface_attr_t *attr)
{
  uct_bxi_iface_t *iface = ucs_derived_of(uct_iface, uct_bxi_iface_t);

  uct_base_iface_query(&iface->super, attr);

  attr->cap.am.max_short = iface->config.max_short - sizeof(uint64_t);
  attr->cap.am.max_bcopy = iface->config.seg_size;
  attr->cap.am.max_zcopy = 0;
  attr->cap.am.max_iov   = iface->config.max_iovecs;

  attr->cap.tag.recv.min_recv   = 0;
  attr->cap.tag.eager.max_short = iface->config.max_short;
  attr->cap.tag.eager.max_bcopy = iface->config.seg_size;
  attr->cap.tag.eager.max_zcopy = iface->config.max_msg_size;
  attr->cap.tag.eager.max_iov   = iface->config.max_iovecs;
  attr->cap.tag.rndv.max_hdr    = 128;
  attr->cap.tag.rndv.max_iov    = 1;
  attr->cap.tag.rndv.max_zcopy  = iface->config.max_msg_size;

  attr->cap.put.max_short       = iface->config.max_short;
  attr->cap.put.max_bcopy       = iface->config.seg_size;
  attr->cap.put.min_zcopy       = 0;
  attr->cap.put.max_zcopy       = iface->config.max_msg_size;
  attr->cap.put.max_iov         = iface->config.max_iovecs;
  attr->cap.put.opt_zcopy_align = 1;
  attr->cap.put.align_mtu       = attr->cap.put.opt_zcopy_align;

  attr->cap.get.max_short       = iface->config.max_short;
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

unsigned uct_bxi_iface_progress(uct_iface_t *super)
{
  return 0;
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

  iface->tm.num_tags = iface->config.tm.max_tags = config->tm.list_size;
  iface->tm.num_op_ctx = iface->config.tm.max_op_ctx = config->tm.max_op_ctx;

  iface->tm.eager_unexp.cb = params->eager_cb;
  iface->tm.rndv_unexp.cb  = params->rndv_cb;
  iface->tm.eager_unexp.arg =
          UCT_IFACE_PARAM_VALUE(params, eager_arg, HW_TM_EAGER_ARG, NULL);
  iface->tm.rndv_unexp.arg =
          UCT_IFACE_PARAM_VALUE(params, rndv_arg, HW_TM_RNDV_ARG, NULL);
  iface->tm.unexpected_cnt     = 0;
  iface->tm.num_outstanding    = 0;
  iface->tm.recv_tried_offload = 0;

  kh_init_inplace(uct_bxi_tag_addrs, &iface->tm.tag_addrs);

  rxq_param = (uct_bxi_rxq_param_t){
          .eqh  = iface->md->eqh,
          .nih  = iface->md->nih,
          .mp   = config->rx.tag_mp,
          .list = PTL_OVERFLOW_LIST,
          .name = "rxq-tag",
  };
  status = uct_bxi_rxq_create(iface, &rxq_param, &iface->rx.tag.queue);

  /* Work pool of operation. */
  mp_param = (ucs_mpool_params_t){
          .max_chunk_size  = iface->tm.num_tags * sizeof(uct_bxi_recv_block_t),
          .elems_per_chunk = iface->tm.num_tags,
          .max_elems       = iface->tm.num_tags,
          .elem_size       = sizeof(uct_bxi_recv_block_t),
          .alignment       = UCS_SYS_CACHE_LINE_SIZE,
          .ops             = &uct_bxi_recv_block_mpool_ops,
          .name            = "recv-block",
          .grow_factor     = 1,
  };
  status = ucs_mpool_init(&mp_param, &iface->tm.recv_block_mp);

out:
  return status;
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
  iface->config.max_short = ucs_min(iface->md->config.limits.max_volatile_size,
                                    UCS_ALLOCA_MAX_SIZE);
  iface->config.device_addr_size = sizeof(uct_bxi_device_addr_t);
  iface->config.iface_addr_size  = sizeof(uct_bxi_iface_addr_t);
  iface->config.ep_addr_size     = sizeof(uct_bxi_ep_addr_t);
}

static void uct_bxi_send_desc_op_handler(uct_bxi_iface_send_op_t *op,
                                         const void              *resp)
{
  /* Because a TX buffer was used, user completion already happened. 
   * So no need to call it. Just put the operation back to MP. */
  ucs_mpool_put_inline(op);
}

void uct_bxi_iface_send_desc_init(ucs_mpool_t *mp, void *obj, void *chunk)
{
  uct_bxi_iface_t *iface =
          ucs_container_of(mp, uct_bxi_iface_t, tx.send_desc_mp);
  uct_bxi_iface_send_op_t *op = obj;

  op->handler  = uct_bxi_send_desc_op_handler;
  op->mem_desc = iface->tx.mem_desc;
}

static ucs_mpool_ops_t uct_bxi_send_desc_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = uct_bxi_iface_send_desc_init,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

static void uct_bxi_send_comp_op_handler(uct_bxi_iface_send_op_t *op,
                                         const void              *resp)
{
  /* First, invoke user completion callback. */
  uct_invoke_completion(op->user_comp, UCS_OK);

  /* Then, we may release the operation. */
  ucs_mpool_put_inline(op);
}

void uct_bxi_iface_send_comp_init(ucs_mpool_t *mp, void *obj, void *chunk)
{
  uct_bxi_iface_t *iface =
          ucs_container_of(mp, uct_bxi_iface_t, tx.send_desc_mp);
  uct_bxi_iface_send_op_t *op = obj;

  op->handler  = uct_bxi_send_comp_op_handler;
  op->mem_desc = iface->tx.mem_desc;
}

static ucs_mpool_ops_t uct_bxi_send_comp_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = uct_bxi_iface_send_comp_init,
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
          .ops             = &uct_bxi_send_comp_mpool_ops,
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
          .max_elems       = iface->config.max_outstanding_ops,
          .elem_size       = sizeof(uct_bxi_iface_send_op_t),
          .alignment       = UCS_SYS_CACHE_LINE_SIZE,
          .ops             = &uct_bxi_send_comp_mpool_ops,
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

UCS_CLASS_INIT_FUNC(uct_bxi_iface_t, uct_iface_ops_t *tl_ops,
                    uct_bxi_iface_ops_t *ops, uct_md_h tl_md,
                    uct_worker_h worker, const uct_iface_params_t *params,
                    const uct_bxi_iface_config_t *uct_config)
{
  ucs_status_t            status = UCS_OK;
  uct_bxi_md_t           *ms     = ucs_derived_of(tl_md, uct_bxi_md_t);
  uct_bxi_iface_config_t *config =
          ucs_derived_of(uct_config, uct_bxi_iface_config_t);
  uct_bxi_mem_desc_param_t mem_desc_param;
  ucs_mpool_params_t       mp_params;
  uct_bxi_rxq_param_t      rxq_param;

  UCS_CLASS_CALL_SUPER_INIT(
          uct_base_iface_t, tl_ops, &ops->super, tl_md, worker, params,
          &config->super UCS_STATS_ARG(
                  ((params->field_mask & UCT_IFACE_PARAM_FIELD_STATS_ROOT) &&
                   (params->stats_root != NULL)) ?
                          params->stats_root :
                          dev->stats)
                   UCS_STATS_ARG(params->mode.device.dev_name));

  /* Initialize all config entries. */
  uct_bxi_iface_config_init(self, config);

  /* Create RX Queues for AM messages. Block are posted to the Priority List */
  rxq_param = (uct_bxi_rxq_param_t){
          .eqh  = self->md->eqh,
          .nih  = self->md->nih,
          .mp   = config->rx.am_mp,
          .list = PTL_PRIORITY_LIST,
          .name = "rxq-am",
  };
  status = uct_bxi_rxq_create(self, &rxq_param, &self->rx.am.queue);
  if (status != UCS_OK) {
    goto err_clean_super;
  }

  /* Initialize TAG resources if enabled. */
  status = uct_bxi_iface_tag_init(self, params, config);
  if (status != UCS_OK) {
    goto err_clean_tag;
  }

  /* Create TX buffers mempool */
  ucs_mpool_params_reset(&mp_params);
  mp_params = (ucs_mpool_params_t){
          .max_chunk_size  = config->tx.mp.max_chunk_size,
          .elems_per_chunk = config->tx.mp.bufs_grow,
          .elem_size = sizeof(uct_bxi_iface_send_op_t) + self->config.seg_size,
          .max_elems = config->tx.mp.max_bufs,
          .alignment = UCS_SYS_CACHE_LINE_SIZE,
          .ops       = &uct_bxi_send_desc_mpool_ops,
          .name      = "send-desc-mp",
          .grow_factor = config->tx.mp.grow_factor,
  };
  status = ucs_mpool_init(&mp_params, &self->tx.send_desc_mp);
  if (status != UCS_OK) {
    goto err_clean_pt;
  }

  status = uct_bxi_iface_tx_ops_init(self, config);
  if (status != UCS_OK) {
    goto err;
  }

  /* Create mempool for pending requests */
  ucs_mpool_params_reset(&mp_params);
  mp_params.elem_size       = sizeof(uct_bxi_pending_req_t);
  mp_params.alignment       = 1;
  mp_params.elems_per_chunk = 128;
  mp_params.ops             = &uct_bxi_pending_mpool_ops;
  mp_params.name            = "pending-ops";
  status                    = ucs_mpool_init(&mp_params, &self->tx.pending_mp);
  if (status != UCS_OK) {
    goto err_cleanup_rx;
  }

  ucs_assert(sizeof(uint64_t) <= sizeof(ptl_hdr_data_t));

err_clean_rxq_am:
  uct_bxi_rxq_fini(self->rx.am.queue);
err:
  return rc;
}

static UCS_CLASS_CLEANUP_FUNC(uct_bxi_iface_t)
{
  return;
}

static UCS_CLASS_DECLARE_DELETE_FUNC(uct_bxi_iface_t, uct_iface_t);

static uct_iface_ops_t uct_bxi_am_iface_tl_ops = {
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
        .iface_tag_create_oop     = uct_bxi_iface_tag_create_oop_ctx,
        .iface_tag_delete_oop     = uct_bxi_iface_tag_delete_oop_ctx,
};

static uct_bxi_iface_ops_t uct_bxi_am_iface_ops = {
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
        .handle_failure = uct_bxi_handle_failure,
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
