#ifndef BXI_IFACE_H
#define BXI_IFACE_H

#include "bxi_md.h"
#include "bxi_rxq.h"

#include <ucs/type/status.h>
#include <uct/base/uct_iface.h>
#include <uct/base/uct_iov.inl>
#include <uct/bxi/ptl_types.h>
#include <unistd.h>

#define UCT_BXI_RNDV_NID_MASK 0xffff
#define UCT_BXI_RNDV_PID_MASK 0xffff

#define UCT_BXI_RNDV_PREFIX 0xdededada
#define UCT_BXI_BUILD_RNDV_CTRL_TAG(_pid)                                      \
  ({                                                                           \
    uint64_t _tag  = 0;                                                        \
    _tag           = UCT_BXI_RNDV_PREFIX;                                      \
    _tag           = _tag << 16;                                               \
    _tag          |= (_pid).phys.nid & UCT_BXI_RNDV_NID_MASK;                  \
    _tag           = _tag << 16;                                               \
    _tag          |= (_pid).phys.pid & UCT_BXI_RNDV_PID_MASK;                  \
    _tag;                                                                      \
  })

#define UCT_BXI_HDR_SET(_hdr, _prot)                                           \
  _hdr  = UCT_BXI_RNDV_PREFIX;                                                 \
  _hdr  = (_hdr << 32);                                                        \
  _hdr |= ((_prot) & 0xf)

static UCS_F_ALWAYS_INLINE int uct_bxi_iface_is_rndv(ptl_hdr_data_t hdr)
{
  return (((hdr & 0xffffffff00000000) >> 32) == UCT_BXI_RNDV_PREFIX);
}

enum {
  UCT_ERR_BXI_CT_FAILURE = UCS_ERR_FIRST_ENDPOINT_FAILURE,
};

/* Operation flags */
enum {
  UCT_BXI_IFACE_SEND_OP_FLAG_INUSE   = UCS_BIT(0),
  UCT_BXI_IFACE_SEND_OP_FLAG_FLUSH   = UCS_BIT(1),
  UCT_BXI_IFACE_SEND_OP_FLAG_EXCL_MD = UCS_BIT(2), /* Send OP used its own MD */
};

typedef enum uct_bxi_tag_prot {
  UCT_BXI_TAG_PROT_EAGER = 0,
  UCT_BXI_TAG_PROT_RNDV_HW,
  UCT_BXI_TAG_PROT_RNDV_SW,
} uct_bxi_tag_prot_t;

typedef struct uct_bxi_iface         uct_bxi_iface_t;
typedef struct uct_bxi_iface_send_op uct_bxi_iface_send_op_t;
typedef struct uct_bxi_ep            uct_bxi_ep_t;
typedef struct uct_bxi_ep_list       uct_bxi_ep_list_t;

typedef void (*handle_failure_func_t)(uct_bxi_iface_t         *iface,
                                      uct_bxi_iface_send_op_t *op,
                                      ptl_ni_fail_t            fail);

typedef void (*uct_bxi_send_op_handler_t)(uct_bxi_iface_send_op_t *op,
                                          const void              *resp);

typedef struct uct_bxi_hdr_rndv {
  unsigned int pti;
  uint64_t     remote_addr;
  size_t       length;
  size_t       header_length;
} uct_bxi_hdr_rndv_t;

typedef struct uct_bxi_pending_req {
  uct_pending_req_t super;
  union {
    struct {
      uct_bxi_ep_t     *ep;
      uct_completion_t *comp;
    } init;
    struct {
      uct_bxi_iface_t   *iface; /* Back pointer to interface */
      ptl_process_t      pid;   /* Initiator PTL identifier */
      ptl_pt_index_t     pti;   /* Initiator PTE from which RNDV was issued */
      uct_tag_t          send_tag; /* Initiator tag */
      size_t             length;   /* Initiator length */
      void              *buffer;   /* Receive buffer */
      uct_tag_context_t *ctx;      /* Tag context from upper layer */
    } tgt;
  };
} uct_bxi_pending_req_t;

typedef struct uct_bxi_pending_purge_arg {
  uct_pending_purge_callback_t cb;
  void                        *arg;
} uct_bxi_pending_purge_arg_t;

typedef struct uct_bxi_iface_addr {
  ptl_pt_index_t am;
  ptl_pt_index_t rma;
  ptl_pt_index_t tag;
  ptl_pt_index_t ctrl;
} uct_bxi_iface_addr_t;

typedef struct uct_bxi_ep_addr {
  uct_bxi_iface_addr_t iface_addr;
} uct_bxi_ep_addr_t;

typedef struct uct_bxi_send_op_comp {
  int                       comp;    /* Number of hits before completion */
  uct_bxi_send_op_handler_t handler; /* Completion function handler */
} uct_bxi_send_op_comp_t;

typedef struct uct_bxi_iface_send_op {
  unsigned               flags;
  uct_bxi_mem_desc_t    *mem_desc;  /* MD on which OP is performed */
  uct_bxi_send_op_comp_t comp;      /* Handler called completion */
  ucs_list_link_t        elem;      /* Element on a TX outstanding list */
  uct_completion_t      *user_comp; /* User completion callback */
  uct_bxi_ep_t          *ep;        /* OP endpoint */
  ptl_size_t             sn;        /* OP sequence number */
  size_t                 length;    /* Length of the OP */

  union {
    struct {
      uct_unpack_callback_t unpack_cb;  /* Unpack callback for GET OP */
      void                 *unpack_arg; /* Unpack user arg for GET OP */
    } get;
    struct {
    } rndv_get;
    struct {
      uct_bxi_recv_block_t *block; /* Necessary in case of OP cancel */
      uct_tag_context_t    *ctx;   /* Tag context attached from target ME. */
      uct_tag_t tag; /* Initiator tag to be passed to target's comp callback. */
    } rndv;
    struct {
      uint64_t value;
      uint64_t compare;
    } atomic;
  };
} uct_bxi_iface_send_op_t;

typedef struct uct_bxi_op_ctx {
  uct_op_ctx_t          super;
  ptl_handle_ct_t       cth;       /* Handle to the OP counter */
  ptl_size_t            threshold; /* Threshold at which OP is triggered */
  uct_bxi_recv_block_t *block;     /* Receive block from rndv protocol */
} uct_bxi_op_ctx_t;

typedef struct uct_bxi_device_addr {
  ptl_process_t pid;
} uct_bxi_device_addr_t;

typedef struct uct_bxi_iface_ops {
  uct_iface_internal_ops_t super;
} uct_bxi_iface_ops_t;

typedef struct uct_bxi_iface_config {
  uct_iface_config_t super;
  size_t             max_events; /* Maximum number event in Event Queue */
  int                seg_size;   /* Max copy-out size of send buffers */

  struct {
    int max_queue_len; /* Maximum number of outstanding OP */
    uct_iface_mpool_config_t mp;
  } tx;

  struct {
    int max_queue_len; /* Maximum number of receive descriptor in the RXQ */
    int num_seg;       /* Number of segments per receive descriptor */
    uct_iface_mpool_config_t am_mp;  /* Receive descriptor for AM RX */
    uct_iface_mpool_config_t tag_mp; /* Receive descriptor for TAG RX */
  } rx;

  int      max_ep_retries;
  int      copyin_buf_per_block;
  int      copyout_buf_per_block;
  int      min_copyin_buf;
  int      max_copyin_buf;
  int      max_copyout_buf;
  unsigned features;
  struct {
    int                      enable;
    unsigned int             list_size;
    unsigned int             max_op_ctx; /* Maximum number of OP context */
    uct_iface_mpool_config_t op_ctx_mp;  /* Receive descriptor for TAG RX. */
  } tm;
} uct_bxi_iface_config_t;

#define uct_bxi_rxq_hash(_ptr) kh_int_hash_func((uint32_t)(_ptr))
KHASH_INIT(uct_bxi_rxq, uint32_t, uct_bxi_rxq_t *, 1, uct_bxi_rxq_hash,
           kh_int_hash_equal)

#define uct_bxi_tag_addr_hash(_ptr) kh_int64_hash_func((uintptr_t)(_ptr))
KHASH_INIT(uct_bxi_tag_addrs, void *, char, 0, uct_bxi_tag_addr_hash,
           kh_int64_hash_equal)

#define uct_bxi_eps_hash(_ptr) kh_int64_hash_func((uint64_t)(_ptr))
KHASH_INIT(uct_bxi_eps, uint64_t, uct_bxi_ep_list_t *, 1, uct_bxi_eps_hash,
           kh_int64_hash_equal)

typedef struct uct_bxi_iface {
  uct_base_iface_t super;
  struct {
    struct {
      int max_events;              /*NOTE: non configurable */
      int max_queue_len;           /* Maximum outstanding operations */
      uct_iface_mpool_config_t mp; /* Memory pool config for TX OP. */
    } tx;

    struct {
      int                      max_queue_len; /* Maximum receive context */
      int                      num_seg; /* Number of segments in RX buffer */
      uct_iface_mpool_config_t am_mp;   /* Memory pool config for AM RX. */
      uct_iface_mpool_config_t tag_mp;  /* Memory pool config for TAG RX. */
    } rx;

    size_t max_events;   /* Maximum number of event in EQ */
    int    max_iovecs;   /* Maximum number of iovec */
    int    max_inline;   /* Maximum short message size */
    int    seg_size;     /* Segment size for eager bcopy/zcopy */
    size_t max_msg_size; /* Maximum message size */
    size_t max_atomic_size;
    struct {
      unsigned int max_op_ctx;
      unsigned int max_tags;
      int          max_zcopy; /* Maximum payload size for zcopy */
    } tm;

    size_t iface_addr_size;
    size_t device_addr_size;
    size_t ep_addr_size;
  } config;

  struct {
    unsigned int               enabled;
    ucs_mpool_t                op_ctx_mp; /* Operation context for Triggered */
    khash_t(uct_bxi_tag_addrs) tag_addrs;
    struct {
      void                    *arg; /* User defined arg */
      uct_tag_unexp_eager_cb_t cb;  /* Callback for unexpected eager messages */
    } eager_unexp;
    struct {
      void                   *arg; /* User defined arg */
      uct_tag_unexp_rndv_cb_t cb;  /* Callback for unexpected rndv messages */
    } rndv_unexp;
    ucs_mpool_t  recv_block_mp;
    unsigned int unexp_hdr_count;
  } tm;

  struct {
    ptl_handle_eq_t     eqh;          /* Event Queue for OP completion. */
    ucs_mpool_t         send_desc_mp; /* Memory pool of send descriptor */
    ucs_mpool_t         send_op_mp;   /* Memory pool of send operations */
    ucs_mpool_t         flush_ops_mp; /* Memory pool for flush OP */
    uct_bxi_mem_desc_t *mem_desc;     /* Memory Descriptor for sending data */
    ucs_mpool_t         pending_mp;   /* Memory pool of pending request */
    ucs_queue_head_t    pending_q;    /* List of pending OP */
    uint64_t            available;    /* Current available send credits */
  } tx;

  struct {
    ptl_handle_eq_t eqh;
    struct {
      uct_bxi_rxq_t *q;
    } am;
    struct {
      uct_bxi_rxq_t  *q;
      ucs_list_link_t cancel; /* List of cancelled block */
    } tag;
    struct {
      uct_bxi_rxq_t *q;
    } ctrl; /* Control RXQ for internal protocols. */
    struct {
      ptl_pt_index_t      pti;
      uct_bxi_mem_entry_t entry;
    } rma;
    khash_t(uct_bxi_rxq) queues; /* Hash table of RX Queues */
  } rx;

  khash_t(uct_bxi_eps) eps;
} uct_bxi_iface_t;

UCS_CLASS_DECLARE(uct_bxi_iface_t, uct_md_h, uct_worker_h,
                  const uct_iface_params_t *, const uct_iface_config_t *);

static UCS_F_ALWAYS_INLINE int
uct_bxi_iface_cmp_iface_addr(uct_bxi_iface_addr_t *addr1,
                             uct_bxi_iface_addr_t *addr2)
{
  return addr1->am == addr2->am && addr1->rma == addr2->rma;
}

static UCS_F_ALWAYS_INLINE int
uct_bxi_iface_cmp_device_addr(uct_bxi_device_addr_t *dev1,
                              uct_bxi_device_addr_t *dev2)
{
  return dev1->pid.phys.pid == dev2->pid.phys.nid &&
         dev1->pid.phys.nid == dev2->pid.phys.nid;
}

ucs_status_t uct_bxi_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                 uct_completion_t *comp);
ucs_status_t uct_bxi_iface_fence(uct_iface_h tl_iface, unsigned flags);

ucs_status_t uct_bxi_iface_add_ep(uct_bxi_iface_t *iface, uct_bxi_ep_t *ep);
void         uct_bxi_iface_ep_remove(uct_bxi_iface_t *iface, uct_bxi_ep_t *ep);

static UCS_F_ALWAYS_INLINE ucs_status_t
uct_bxi_iface_tag_add_to_hash(uct_bxi_iface_t *iface, void *buffer)
{
  int ret;
  kh_put(uct_bxi_tag_addrs, &iface->tm.tag_addrs, buffer, &ret);
  if (ucs_unlikely(ret == UCS_KH_PUT_KEY_PRESENT)) {
    /* Do not post the same buffer more than once (even with different tags)
     * to avoid memory corruption. */
    return UCS_ERR_ALREADY_EXISTS;
  }
  ucs_assert(ret != UCS_KH_PUT_FAILED);
  return UCS_OK;
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_iface_tag_del_from_hash(uct_bxi_iface_t *iface, void *buffer)
{
  khiter_t iter;

  iter = kh_get(uct_bxi_tag_addrs, &iface->tm.tag_addrs, buffer);
  ucs_assert(iter != kh_end(&iface->tm.tag_addrs));
  kh_del(uct_bxi_tag_addrs, &iface->tm.tag_addrs, iter);
}

static UCS_F_ALWAYS_INLINE size_t uct_bxi_fill_ptl_iovec(ptl_iovec_t *ptl_iov,
                                                         const uct_iov_t *iov,
                                                         size_t iovcnt)
{
  size_t iov_it, ptl_it = 0;

  for (iov_it = 0; iov_it < iovcnt; ++iov_it) {
    ptl_iov[ptl_it].iov_len = uct_iov_get_length(&iov[iov_it]);
    if (ptl_iov[ptl_it].iov_len > 0) {
      ptl_iov[ptl_it].iov_base = (void *)(iov[iov_it].buffer);
    } else {
      continue; /* to avoid zero length elements in iov */
    }
    ++ptl_it;
  }

  return ptl_it;
}

static UCS_F_ALWAYS_INLINE int uct_bxi_iface_should_poll_tx(unsigned count)
{
  return (count == 0);
}

static UCS_F_ALWAYS_INLINE int
uct_bxi_iface_tx_need_flush(uct_bxi_iface_t *iface)
{
  return (iface->tx.available != iface->config.tx.max_queue_len);
}

static UCS_F_ALWAYS_INLINE uint64_t
uct_bxi_iface_available(uct_bxi_iface_t *iface)
{
  return iface->tx.available;
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_iface_available_add(uct_bxi_iface_t *iface, uint64_t count)
{
  iface->tx.available += count;
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_iface_available_set(uct_bxi_iface_t *iface, uint64_t count)
{
  iface->tx.available = count;
}

extern ucs_config_field_t uct_bxi_iface_common_config_table[];
extern ucs_config_field_t uct_bxi_iface_config_table[];

#define uct_bxi_iface_md(iface) ucs_derived_of(iface->super.md, uct_bxi_md_t)

#define uct_bxi_iface_trace_am(_iface, _type, _am_id, _data, _length)          \
  uct_iface_trace_am(&(_iface)->super, _type, _am_id, _data, _length, "%cX",   \
                     ((_type) == UCT_AM_TRACE_TYPE_RECV) ? 'R' :               \
                     ((_type) == UCT_AM_TRACE_TYPE_SEND) ? 'T' :               \
                                                           '?')

#define UCT_BXI_CHECK_IFACE_RES(_iface)                                        \
  if (uct_bxi_iface_available(_iface) <= 0) {                                  \
    return UCS_ERR_NO_RESOURCE;                                                \
  }

#define UCT_BXI_CHECK_ZCOPY_DATA(_iovcnt, _max_iov, _func_name, _length,       \
                                 _seg_size)                                    \
  UCT_CHECK_IOV_SIZE(_iovcnt, _max_iov, _func_name);                           \
  UCT_CHECK_LENGTH(_length, 0, _seg_size, "zcopy payload");

#define UCT_BXI_CHECK_IFACE_RES_PTR(_iface)                                    \
  if (uct_bxi_iface_available(_iface) <= 0) {                                  \
    return UCS_STATUS_PTR(UCS_ERR_NO_RESOURCE);                                \
  }

//FIXME: rework all these macros...
#define UCT_BXI_IFACE_GET_TX_DESC(_iface, _mp, _desc)                          \
  UCT_TL_IFACE_GET_TX_DESC(&(_iface)->super.super, _mp, _desc,                 \
                           return UCS_ERR_NO_RESOURCE);

#define UCT_BXI_IFACE_GET_TX_DESC_PTR(_iface, _mp, _desc)                      \
  UCT_TL_IFACE_GET_TX_DESC(&(_iface)->super.super, _mp, _desc,                 \
                           return UCS_STATUS_PTR(UCS_ERR_NO_RESOURCE));

#define UCT_BXI_IFACE_GET_TX_DESC_ERR(_iface, _mp, _desc, _err)                \
  UCT_TL_IFACE_GET_TX_DESC(&(_iface)->super.super, _mp, _desc, _err);

#define UCT_BXI_IFACE_GET_TX_AM_BCOPY_DESC(_iface, _mp, _desc, _ep, _pack_cb,  \
                                           _arg, _length)                      \
  ({                                                                           \
    UCT_BXI_IFACE_GET_TX_DESC(_iface, _mp, _desc)                              \
    (_desc)->comp.comp    = 1;                                                 \
    (_desc)->comp.handler = uct_bxi_send_op_no_completion;                     \
    (_desc)->ep           = _ep;                                               \
    *(_length)            = _pack_cb(_desc + 1, _arg);                         \
  })

#define UCT_BXI_IFACE_GET_TX_PUT_BCOPY_DESC(_iface, _mp, _desc, _ep, _pack_cb, \
                                            _arg, _length)                     \
  UCT_BXI_IFACE_GET_TX_DESC(_iface, _mp, _desc)                                \
  (_desc)->comp.comp    = 1;                                                   \
  (_desc)->comp.handler = uct_bxi_send_op_no_completion;                       \
  (_desc)->ep           = _ep;                                                 \
  _length               = _pack_cb(_desc + 1, _arg);                           \
  UCT_SKIP_ZERO_LENGTH(_length, _desc);

#define UCT_BXI_IFACE_GET_TX_GET_BCOPY_DESC(_iface, _mp, _desc, _ep,             \
                                            _unpack_cb, _comp, _arg, _length)    \
  UCT_BXI_IFACE_GET_TX_DESC(_iface, _mp, _desc)                                  \
  ucs_assert(_length <= (_iface)->config.seg_size);                              \
  (_desc)->ep             = _ep;                                                 \
  (_desc)->comp.comp      = 1;                                                   \
  (_desc)->comp.handler   = (_comp == NULL) ?                                    \
                                    uct_bxi_ep_get_bcopy_handler_no_completion : \
                                    uct_bxi_ep_get_bcopy_handler;                \
  (_desc)->user_comp      = _comp;                                               \
  (_desc)->length         = _length;                                             \
  (_desc)->get.unpack_arg = _arg;                                                \
  (_desc)->get.unpack_cb  = _unpack_cb;

#define UCT_BXI_IFACE_GET_TX_OP(_iface, _mp, _desc, _ep, _length)              \
  UCT_BXI_IFACE_GET_TX_DESC(_iface, _mp, _desc)                                \
  (_desc)->ep           = _ep;                                                 \
  (_desc)->comp.comp    = 1;                                                   \
  (_desc)->comp.handler = uct_bxi_send_op_no_completion;                       \
  UCT_SKIP_ZERO_LENGTH(_length, _desc);

#define UCT_BXI_IFACE_GET_TX_OP_COMP(_iface, _mp, _desc, _ep, _user_comp,      \
                                     _handler, _length)                        \
  UCT_BXI_IFACE_GET_TX_DESC(_iface, _mp, _desc)                                \
  (_desc)->ep        = _ep;                                                    \
  (_desc)->comp.comp = 1;                                                      \
  (_desc)->comp.handler =                                                      \
          (_user_comp == NULL) ? uct_bxi_send_op_no_completion : _handler;     \
  (_desc)->user_comp = _user_comp;                                             \
  UCT_SKIP_ZERO_LENGTH(_length, _desc);

#define UCT_BXI_IFACE_GET_TX_TAG_OP_COMP(_iface, _mp, _desc, _ep, _user_comp,  \
                                         _handler, _length)                    \
  UCT_BXI_IFACE_GET_TX_DESC(_iface, _mp, _desc)                                \
  (_desc)->ep        = _ep;                                                    \
  (_desc)->comp.comp = 1;                                                      \
  (_desc)->comp.handler =                                                      \
          (_user_comp == NULL) ? uct_bxi_send_op_no_completion : _handler;     \
  (_desc)->user_comp = _user_comp;

#define UCT_BXI_IFACE_GET_TX_TAG_DESC_ERR(_iface, _mp, _desc, _ep, _user_comp, \
                                          _handler, _err)                      \
  UCT_BXI_IFACE_GET_TX_DESC_ERR(_iface, _mp, _desc, _err)                      \
  (_desc)->ep        = _ep;                                                    \
  (_desc)->comp.comp = 1;                                                      \
  (_desc)->comp.handler =                                                      \
          (_user_comp == NULL) ? uct_bxi_send_op_no_completion : _handler;     \
  (_desc)->user_comp = _user_comp;

#define UCT_BXI_IFACE_GET_RX_TAG_DESC(_iface, _mp, _desc, _rxq)                \
  UCT_TL_IFACE_GET_TX_DESC(&(_iface)->super.super, _mp, _desc,                 \
                           return UCS_ERR_NO_RESOURCE);                        \
  (_desc)->rxq = _rxq;

#define UCT_BXI_IFACE_GET_RX_TAG_DESC_PTR(_iface, _mp, _desc, _rxq, _err_code) \
  UCT_TL_IFACE_GET_TX_DESC(&(_iface)->super.super, _mp, _desc, _err_code);     \
  (_desc)->rxq = _rxq;

#define UCT_BXI_CHECK_IOV_SIZE_PTR(_iovcnt, _max_iov, _name)                   \
  UCT_CHECK_PARAM_PTR((_iovcnt) <= (_max_iov),                                 \
                      "iovcnt(%lu) should be limited by %lu in %s", _iovcnt,   \
                      _max_iov, _name)

#endif
