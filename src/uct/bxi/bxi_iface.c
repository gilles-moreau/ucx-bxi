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

        {"MAX_OUTSTANDING_OPS", "512",
         "Maximum number of outstanding operations (default: 2048).",
         ucs_offsetof(uct_bxi_iface_config_t, max_outstanding_ops),
         UCS_CONFIG_TYPE_UINT},

        {"COPYIN_BUF_PER_BLOCK", "8",
         "Number of copyin buffers allocated per block (default: 2)",
         ucs_offsetof(uct_bxi_iface_config_t, copyin_buf_per_block),
         UCS_CONFIG_TYPE_UINT},

        {"COPYOUT_BUF_PER_BLOCK", "8",
         "Number of copyout buffers allocated per block (default: 2)",
         ucs_offsetof(uct_bxi_iface_config_t, copyout_buf_per_block),
         UCS_CONFIG_TYPE_UINT},

        {"MIN_COPYIN_BUF", "2",
         "Minimum number of copyin buffers per working queues (default: 2)",
         ucs_offsetof(uct_bxi_iface_config_t, min_copyin_buf),
         UCS_CONFIG_TYPE_UINT},

        {"MAX_COPYIN_BUF", "8",
         "Maximum number of copyin buffers per working queues (default: 8)",
         ucs_offsetof(uct_bxi_iface_config_t, max_copyin_buf),
         UCS_CONFIG_TYPE_UINT},

        {"MAX_COPYOUT_BUF", "64",
         "Maximum number of copyout buffers per working queues (default: 8)",
         ucs_offsetof(uct_bxi_iface_config_t, max_copyout_buf),
         UCS_CONFIG_TYPE_UINT},

        {"NUM_EAGER_BLOCKS", "32",
         "Number of eager blocks for receiving unexpected messages (default: "
         "32).",
         ucs_offsetof(uct_bxi_iface_config_t, num_eager_blocks),
         UCS_CONFIG_TYPE_UINT},

        {"EAGER_BLOCK_SIZE", "8192",
         "Size of a single eager block (default: 8192).",
         ucs_offsetof(uct_bxi_iface_config_t, eager_block_size),
         UCS_CONFIG_TYPE_UINT},

        {"MAX_EP_RETRIES", "16",
         "Maximum nunber of send retry on a given endpoint (default: 16).",
         ucs_offsetof(uct_bxi_iface_config_t, max_ep_retries),
         UCS_CONFIG_TYPE_UINT},

        {NULL},
};

ucs_status_t uct_bxi_iface_query(uct_iface_h uct_iface, uct_iface_attr_t *attr)
{
  uct_bxi_iface_t *iface = ucs_derived_of(uct_iface, uct_bxi_iface_t);

  uct_base_iface_query(&iface->super, attr);

  attr->cap.am.max_short = iface->config.max_short - sizeof(uint64_t);
  attr->cap.am.max_bcopy = iface->config.eager_block_size;
  attr->cap.am.max_zcopy = 0;
  attr->cap.am.max_iov   = iface->config.max_iovecs;

  attr->cap.tag.recv.min_recv   = 0;
  attr->cap.tag.eager.max_short = iface->config.max_short;
  attr->cap.tag.eager.max_bcopy = iface->config.eager_block_size;
  attr->cap.tag.eager.max_zcopy = iface->config.max_msg_size;
  attr->cap.tag.eager.max_iov   = iface->config.max_iovecs;
  attr->cap.tag.rndv.max_hdr    = 128;
  attr->cap.tag.rndv.max_iov    = 1;
  attr->cap.tag.rndv.max_zcopy  = iface->config.max_msg_size;

  attr->cap.put.max_short       = iface->config.max_short;
  attr->cap.put.max_bcopy       = iface->config.eager_block_size;
  attr->cap.put.min_zcopy       = 0;
  attr->cap.put.max_zcopy       = iface->config.max_msg_size;
  attr->cap.put.max_iov         = iface->config.max_iovecs;
  attr->cap.put.opt_zcopy_align = 1;
  attr->cap.put.align_mtu       = attr->cap.put.opt_zcopy_align;

  attr->cap.get.max_short       = iface->config.max_short;
  attr->cap.get.max_bcopy       = iface->config.eager_block_size;
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
  addr->am  = uct_bxi_rxq_get_addr(iface->rx.am.rxq);
  addr->tag = uct_bxi_rxq_get_addr(iface->rx.tag.rxq);

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
