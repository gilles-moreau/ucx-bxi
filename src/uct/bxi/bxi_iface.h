#ifndef BXI_IFACE_H
#define BXI_IFACE_H

#include "bxi_md.h"
#include "bxi_rxq.h"

#include <uct/base/uct_iov.inl>

#define UCT_BXI_MD_PACKED_RKEY_SIZE sizeof(uint64_t) + sizeof(void *)

#define UCT_BXI_RNDV_LENGTH_MASK   0xfffffffffful
#define UCT_BXI_RNDV_CONN_KEY_MASK 0xfffful
#define UCT_BXI_RNDV_CNT_MASK      0xfffful
#define UCT_BXI_RNDV_PTI_MASK      0xfful

#define UCT_BXI_RNDV_SW_HDR         0xdeadbeefdeadbeef
#define UCT_BXI_RNDV_MAX_HDR_LENGTH 128 /* Bytes */

#define UCT_BXI_RNDV_LENGTH_GET(_hdr)                                          \
  (((_hdr) >> 24) & UCT_BXI_RNDV_LENGTH_MASK)
#define UCT_BXI_RNDV_CONN_KEY_GET(_hdr)                                        \
  (((_hdr) >> 8) & UCT_BXI_RNDV_CONN_KEY_MASK)
#define UCT_BXI_RNDV_PTI_GET(_hdr) ((_hdr) & UCT_BXI_RNDV_PTI_MASK)

#define UCT_BXI_RNDV_HDR_SET(_hdr, _length, _conn_key, _pti)                   \
  _hdr  = ((_length) & UCT_BXI_RNDV_LENGTH_MASK);                              \
  _hdr  = (_hdr << 16);                                                        \
  _hdr |= ((_conn_key) & UCT_BXI_RNDV_CONN_KEY_MASK);                          \
  _hdr  = (_hdr << 8);                                                         \
  _hdr |= ((_pti) & UCT_BXI_RNDV_PTI_MASK);

#define UCT_BXI_RNDV_TAG_SET(_tag, _pti, _conn_key, _cnt)                      \
  _tag  = 0;                                                                   \
  _tag |= ((_pti) & UCT_BXI_RNDV_PTI_MASK);                                    \
  _tag  = (_tag << 8);                                                         \
  _tag |= ((_conn_key) & UCT_BXI_RNDV_CONN_KEY_MASK);                          \
  _tag  = (_tag << 16);                                                        \
  _tag |= ((_cnt) & UCT_BXI_RNDV_CNT_MASK);

/* Operation flags */
enum {
  UCT_BXI_IFACE_SEND_OP_FLAG_INUSE     = UCS_BIT(0),
  UCT_BXI_IFACE_SEND_OP_FLAG_FLUSH     = UCS_BIT(1),
  UCT_BXI_IFACE_SEND_OP_FLAG_CANCELLED = UCS_BIT(2),
};

typedef struct uct_bxi_iface         uct_bxi_iface_t;
typedef struct uct_bxi_iface_send_op uct_bxi_iface_send_op_t;
typedef struct uct_bxi_ep            uct_bxi_ep_t;

typedef void (*uct_bxi_send_op_handler_t)(uct_bxi_iface_send_op_t *op,
                                          const void              *resp);

typedef struct uct_bxi_hdr_rndv {
  uint64_t     remote_addr;
  unsigned int header_length;
  char         rkey[UCT_BXI_MD_PACKED_RKEY_SIZE]; // Remote key follows
} uct_bxi_hdr_rndv_t;

typedef struct uct_bxi_pending_req {
  uct_pending_req_t super;
  uct_bxi_ep_t     *ep;
  uct_completion_t *comp;
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
  uct_bxi_iface_t       *iface;     /* Backpointer */
  uct_bxi_send_op_comp_t comp;      /* Handler called completion */
  ucs_list_link_t        elem;      /* Element on a TX outstanding list */
  uct_completion_t      *user_comp; /* User completion callback */
  uct_bxi_ep_t          *ep;        /* OP endpoint */
  size_t                 length;    /* Length of the OP */

  union {
    struct {
      uct_unpack_callback_t unpack_cb;  /* Unpack callback for GET OP */
      void                 *unpack_arg; /* Unpack user arg for GET OP */
    } get;
    struct {
      uct_bxi_recv_block_t *block; /* Used for completion and OP cancel */
    } rndv;
    struct {
      uint64_t value;
      uint64_t compare;
    } atomic;
  };
} uct_bxi_iface_send_op_t;

typedef struct uct_bxi_gop {
  uct_gop_t             super;    /* Generic operation handle */
  ptl_handle_ct_t       cth;      /* Counter handle */
  ptl_size_t            ct_value; /* SW value tracking HW counter value */
  uct_bxi_recv_block_t *block;    /* Receive block from rndv protocol */
} uct_bxi_gop_t;

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

  int      copyin_buf_per_block;
  int      copyout_buf_per_block;
  int      min_copyin_buf;
  int      max_copyin_buf;
  int      max_copyout_buf;
  unsigned features;
  struct {
    int                      enable;
    unsigned int             list_size;
    unsigned int             max_gop; /* Maximum number of OP context */
    unsigned int             max_rndv_hdr;
    uct_iface_mpool_config_t gop_mp; /* Receive descriptor for TAG RX. */
  } tm;
} uct_bxi_iface_config_t;

#define uct_bxi_tag_addr_hash(_ptr) kh_int64_hash_func((uintptr_t)(_ptr))
KHASH_INIT(uct_bxi_tag_addrs, void *, char, 0, uct_bxi_tag_addr_hash,
           kh_int64_hash_equal)

#define UCT_BXI_RNDV_CONN_SN_PTI_MASK 0xff
#define UCT_BXI_RNDV_CONN_SN_CNT_MASK 0xff

#define UCT_BXI_CONN_SN_SET(_conn_sn, _pti, _cnt)                              \
  _conn_sn  = 0;                                                               \
  _conn_sn |= ((_conn_sn) & UCT_BXI_RNDV_CONN_SN_PTI_MASK);                    \
  _conn_sn  = (_conn_sn << 8);                                                 \
  _conn_sn |= ((_cnt) & UCT_BXI_RNDV_CONN_SN_CNT_MASK);

/* Triplet to access a rendezvous counter. */
typedef struct uct_bxi_conn_id {
  ptl_process_t     pid;      /* Portals Process ID */
  ptl_pt_index_t    pti;      /* Portals Table Index */
  uct_ep_conn_key_t conn_key; /* Connection key */
} uct_bxi_conn_id_t;

typedef struct uct_bxi_rndv_cnt {
  struct {
    uct_bxi_conn_id_t cid;  /* Counter connection ID */
    uint16_t          recv; /* Counter of receive rndv requests */
    uint16_t          send; /* Counter of send rndv requests */
  };
} uct_bxi_rndv_cnt_t;

KHASH_DECLARE(uct_bxi_conn_map, uct_bxi_rndv_cnt_t *, char);

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
      size_t       eager_limit; /* Maximum eager message size. */
      unsigned int max_gop;     /* Maximum number of generic operation */
      unsigned int max_tags;    /* Maximum number of hw matching descriptors */
      int          max_zcopy;   /* Maximum payload size for zcopy */
      unsigned     max_hdr;     /* Maximum header size for rndv send */
    } tm;

    size_t iface_addr_size;
    size_t device_addr_size;
    size_t ep_addr_size;
    size_t max_num_eps;
  } config;

  struct {
    unsigned int               enabled;
    ucs_mpool_t                gop_mp; /* Operation context for Triggered */
    khash_t(uct_bxi_tag_addrs) tag_addrs;
    struct {
      void                    *arg; /* User defined arg */
      uct_tag_unexp_eager_cb_t cb;  /* Callback for unexpected eager messages */
    } eager_unexp;
    struct {
      void                   *arg; /* User defined arg */
      uct_tag_unexp_rndv_cb_t cb;  /* Callback for unexpected rndv messages */
    } rndv_unexp;
    ucs_mpool_t  recv_block_mp;   /* MP of exp block */
    ptl_event_t *unexp_ev;        /* Cached unexp event, used for cancel */
    unsigned int rndv_hdr_offset; /* Offset of rndv hdr in payload */
    int          sched_window;    /* Is scheduling window opened? */
    khash_t(uct_bxi_conn_map) conn_map; /* Connection map */
  } tm;                                 /* Tag matching */

  struct {
    ptl_handle_eq_t     eqh;          /* Event Queue for OP completion. */
    ucs_mpool_t         send_desc_mp; /* Memory pool of send descriptor */
    ucs_mpool_t         send_op_mp;   /* Memory pool of send operations */
    void               *short_desc;   /* Preallocated buffer for short am */
    ucs_mpool_t         flush_ops_mp; /* Memory pool for flush OP */
    uct_bxi_mem_desc_t *mem_desc;     /* Memory Descriptor for sending data */
    ucs_mpool_t         pending_mp;   /* Memory pool of pending request */
    uint64_t            available;    /* Current available send credits */
  } tx;

  struct {
    ptl_handle_eq_t eqh;
    struct {
      uct_bxi_rxq_t *q;
    } am;
    struct {
      uct_bxi_rxq_t *q;
    } tag;
    struct {
      uct_bxi_rxq_t *q;
    } ctrl; /* Control RXQ for internal protocols. */
    struct {
      ptl_pt_index_t      pti;
      uct_bxi_mem_entry_t entry;
    } rma;
  } rx;
  size_t          num_eps;
  ucs_list_link_t eps; /* List of uct ep */
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

unsigned uct_bxi_iface_progress(uct_iface_t *super);

ucs_status_t uct_bxi_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                 uct_completion_t *comp);
ucs_status_t uct_bxi_iface_fence(uct_iface_h tl_iface, unsigned flags);

ucs_status_t uct_bxi_iface_block_handle_tag_exp(uct_bxi_iface_t      *iface,
                                                uct_bxi_recv_block_t *block,
                                                ptl_event_t          *ev);

ucs_status_t uct_bxi_iface_tag_init(uct_bxi_iface_t              *iface,
                                    const uct_iface_params_t     *params,
                                    const uct_bxi_iface_config_t *config);

void uct_bxi_iface_tag_fini(uct_bxi_iface_t *iface);

static UCS_F_ALWAYS_INLINE ucs_status_t
uct_bxi_iface_tag_add_to_hash(uct_bxi_iface_t *iface, void *buffer)
{
  int ret;

  /* Dot not add NULL buffer. */
  if (buffer == NULL) {
    return UCS_OK;
  }

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

  if (buffer == NULL) {
    return;
  }

  iter = kh_get(uct_bxi_tag_addrs, &iface->tm.tag_addrs, buffer);
  ucs_assert(iter != kh_end(&iface->tm.tag_addrs));
  kh_del(uct_bxi_tag_addrs, &iface->tm.tag_addrs, iter);
}

//TODO: use khash map specific implementation
static UCS_F_ALWAYS_INLINE int uct_bxi_iface_is_rndv_hw(uct_bxi_iface_t *iface,
                                                        ptl_event_t     *ev)
{
  return ev->rlength == iface->config.tm.eager_limit + 1;
}

static UCS_F_ALWAYS_INLINE int uct_bxi_iface_is_rndv_sw(ptl_hdr_data_t hdr)
{
  return hdr == UCT_BXI_RNDV_SW_HDR;
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_rndv_inc_send_cnt(uct_bxi_iface_t *iface, uct_bxi_rndv_cnt_t *cnt)
{
  cnt->send++;
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_rndv_inc_recv_cnt(uct_bxi_iface_t *iface, uct_bxi_rndv_cnt_t *cnt)
{
  cnt->recv++;
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_rndv_dec_recv_cnt(uct_bxi_iface_t *iface, uct_bxi_rndv_cnt_t *cnt)
{
  cnt->recv--;
}

static UCS_F_ALWAYS_INLINE size_t uct_bxi_fill_ptl_iovec(ptl_iovec_t *ptl_iov,
                                                         const uct_iov_t *iov,
                                                         size_t iovcnt)
{
  size_t iov_it, ptl_it = 0;
#ifdef HAVE_GDR_COPY
  size_t         bar_offset;
  uct_bxi_mem_t *memh;

  for (iov_it = 0; iov_it < iovcnt; ++iov_it) {
    memh                     = (uct_bxi_mem_t *)iov[iov_it].memh;
    ptl_iov[ptl_it].iov_len  = uct_iov_get_length(&iov[iov_it]);
    ptl_iov[ptl_it].iov_base = NULL;
    if (ptl_iov[ptl_it].iov_len > 0) {
      if ((void *)memh == (void *)0xdeadbeef) {
        ptl_iov[ptl_it].iov_base = (void *)(iov[iov_it].buffer);
      } else {
        bar_offset = (size_t)(iov[iov_it].buffer - memh->info.va);
        ptl_iov[ptl_it].iov_base =
                UCS_PTR_BYTE_OFFSET(memh->bar_ptr, bar_offset);
      }
    } else {
      continue; /* to avoid zero length elements in iov */
    }
    ++ptl_it;
  }
#else
  for (iov_it = 0; iov_it < iovcnt; ++iov_it) {
    ptl_iov[ptl_it].iov_len  = uct_iov_get_length(&iov[iov_it]);
    ptl_iov[ptl_it].iov_base = NULL;
    if (ptl_iov[ptl_it].iov_len > 0) {
      ptl_iov[ptl_it].iov_base = (void *)(iov[iov_it].buffer);
    } else {
      continue; /* to avoid zero length elements in iov */
    }
    ++ptl_it;
  }
#endif

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
uct_bxi_iface_has_tx_resources(uct_bxi_iface_t *iface)
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

static UCS_F_ALWAYS_INLINE void
uct_bxi_ep_remove_from_queue(uct_bxi_iface_send_op_t *op)
{
  ucs_list_del(&op->elem);
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_iface_release_op(uct_bxi_iface_send_op_t *op)
{
  uct_bxi_iface_available_add(op->iface, 1);
  op->flags = 0;
  ucs_mpool_put_inline(op);
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_iface_completion_op(uct_bxi_iface_send_op_t *op)
{
  ucs_assertv(op->flags & UCT_BXI_IFACE_SEND_OP_FLAG_INUSE, "op=%p", op);

  if (--op->comp.comp == 0) {
    op->comp.handler(op, op + 1);
    uct_bxi_iface_release_op(op);
  }
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_iface_release_flush_op(uct_bxi_iface_send_op_t *op)
{
  op->flags = 0;
  ucs_mpool_put_inline(op);
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_iface_completion_flush_op(uct_bxi_iface_send_op_t *op)
{
  ucs_assert(op->flags & UCT_BXI_IFACE_SEND_OP_FLAG_INUSE);

  op->comp.handler(op, op + 1);
  uct_bxi_iface_release_flush_op(op);
}

ucs_status_t uct_bxi_iface_get_rndv_cnt(uct_bxi_iface_t     *iface,
                                        uct_bxi_conn_id_t    cid,
                                        uct_bxi_rndv_cnt_t **cnt_p);

/* Complete a hardware initiated rendezvous. */
static UCS_F_ALWAYS_INLINE void
uct_bxi_iface_complete_rndv(uct_bxi_iface_t *iface, uct_bxi_recv_block_t *block,
                            ptl_hdr_data_t hdr, ptl_match_bits_t tag,
                            ptl_process_t initiator, size_t send_size)
{
  ucs_status_t   status;
  ptl_pt_index_t pti;

  /* Retrieve protocol data. */
  pti = UCT_BXI_RNDV_PTI_GET(hdr);

  //TODO: GPU/CPU compatibility, see uct_bxi_pack_rndv.
  //if (block->mem_type == UCS_MEMORY_TYPE_HOST) {
  //  start = (ptl_size_t)UCS_PTR_BYTE_OFFSET(block->start,
  //                                         iface->tm.rndv_hdr_offset);
  //  length = ucs_min(send_size, block->size);
  //  length = ucs_max((ssize_t)(length - iface->tm.rndv_hdr_offset), 0);
  //} else {
  //  ucs_assert(block->mem_type == UCS_MEMORY_TYPE_CUDA);
  //  start = (ptl_size_t)block->start;
  //  length = send_size;
  //}

  //FIXME: get has to be performed on the block MD in order for the hw counter
  //       to be incremented and for the sw counter to keep track of it.
  status = uct_bxi_wrap(PtlGet(block->mdh, (ptl_size_t)block->start,
                               block->size, initiator, pti, tag, 0, block->op));
  if (status != UCS_OK) {
    ucs_fatal("BXI: sw rndv get failed");
  }
}

extern ucs_config_field_t uct_bxi_iface_common_config_table[];
extern ucs_config_field_t uct_bxi_iface_config_table[];

#define uct_bxi_iface_md(iface) ucs_derived_of(iface->super.md, uct_bxi_md_t)

#define uct_bxi_iface_trace_am(_iface, _type, _am_id, _data, _length)          \
  uct_iface_trace_am(&(_iface)->super, _type, _am_id, _data, _length, "%cX",   \
                     ((_type) == UCT_AM_TRACE_TYPE_RECV) ? 'R' :               \
                     ((_type) == UCT_AM_TRACE_TYPE_SEND) ? 'T' :               \
                                                           '?')
// Check macros
#define UCT_BXI_CHECK_LENGTH_PTR(_length, _min_length, _max_length, _name)     \
  {                                                                            \
    typeof(_length) __length = _length;                                        \
    UCT_CHECK_PARAM_PTR((_length) <= (_max_length),                            \
                        "Invalid %s length: %zu (expected: <= %zu)", _name,    \
                        (size_t)(__length), (size_t)(_max_length));            \
    UCT_CHECK_PARAM_PTR((ssize_t)(_length) >= (_min_length),                   \
                        "Invalid %s length: %zu (expected: >= %zu)", _name,    \
                        (size_t)(__length), (size_t)(_min_length));            \
  }

#define UCT_BXI_CHECK_AM_SHORT(_am_id, _length, _header_t, _max_inline)        \
  UCT_CHECK_AM_ID(_am_id);                                                     \
  UCT_CHECK_LENGTH(sizeof(_header_t) + _length, 0, _max_inline, "am_short");

#define UCT_BXI_CHECK_IOV_SIZE_PTR(_iovcnt, _max_iov, _name)                   \
  UCT_CHECK_PARAM_PTR((_iovcnt) <= (_max_iov),                                 \
                      "iovcnt(%lu) should be limited by %lu in %s", _iovcnt,   \
                      _max_iov, _name)

#define UCT_BXI_CHECK_RNDV_DATA(_iovcnt, _max_iov, _length, _max_len)          \
  UCT_BXI_CHECK_IOV_SIZE_PTR(_iovcnt, _max_iov, "uct_bxi_ep_tag_rndv_zcopy");  \
  UCT_BXI_CHECK_LENGTH_PTR(_length, 0, _max_len, "rndv_zcopy");

#define UCT_BXI_CHECK_IFACE_RES(_iface, _ep)                                   \
  if (uct_bxi_iface_has_tx_resources(_iface) <= 0) {                           \
    UCS_STATS_UPDATE_COUNTER((_ep)->super.stats, UCT_EP_STAT_NO_RES, 1);       \
    return UCS_ERR_NO_RESOURCE;                                                \
  }

#define UCT_BXI_CHECK_IFACE_RES_PTR(_iface, _ep)                               \
  if (uct_bxi_iface_has_tx_resources(_iface) <= 0) {                           \
    UCS_STATS_UPDATE_COUNTER((_ep)->super.stats, UCT_EP_STAT_NO_RES, 1);       \
    return UCS_STATUS_PTR(UCS_ERR_NO_RESOURCE);                                \
  }

// Get descriptor macros
#define UCT_BXI_IFACE_GET_TX_DESC(_iface, _mp, _desc)                          \
  UCT_TL_IFACE_GET_TX_DESC(&(_iface)->super, _mp, _desc,                       \
                           return UCS_ERR_NO_RESOURCE);

#define UCT_BXI_IFACE_GET_TX_DESC_ERR(_iface, _mp, _desc, _err)                \
  UCT_TL_IFACE_GET_TX_DESC(&(_iface)->super, _mp, _desc, _err);

#define UCT_BXI_IFACE_INIT_TX_DESC(_desc, _ep, _handler)                       \
  (_desc)->comp.comp    = 1;                                                   \
  (_desc)->comp.handler = _handler;                                            \
  (_desc)->ep           = _ep;

#define UCT_BXI_IFACE_GET_TX_BCOPY_DESC(_iface, _mp, _desc, _ep, _pack_cb,     \
                                        _arg, _handler, _length)               \
  ({                                                                           \
    UCT_BXI_IFACE_GET_TX_DESC(_iface, _mp, _desc)                              \
    UCT_BXI_IFACE_INIT_TX_DESC(_desc, _ep, _handler)                           \
    (_desc)->user_comp = NULL;                                                 \
    *(_length)         = _pack_cb(_desc + 1, _arg);                            \
  })

#define UCT_BXI_IFACE_GET_TX_GET_BCOPY_DESC(                                   \
        _iface, _mp, _desc, _ep, _unpack_cb, _handler, _comp, _arg, _length)   \
  UCT_BXI_IFACE_GET_TX_DESC(_iface, _mp, _desc)                                \
  ucs_assert(_length <= (_iface)->config.seg_size);                            \
  UCT_BXI_IFACE_INIT_TX_DESC(_desc, _ep, _handler)                             \
  (_desc)->user_comp      = _comp;                                             \
  (_desc)->length         = _length;                                           \
  (_desc)->get.unpack_arg = _arg;                                              \
  (_desc)->get.unpack_cb  = _unpack_cb;

#define UCT_BXI_IFACE_GET_TX_TAG_BCOPY_DESC_ERR(                               \
        _iface, _mp, _desc, _ep, _user_comp, _handler, _pack_cb, _src, _len,   \
        _memh, _hdr, _hdrlen, _pack_length, _err)                              \
  ({                                                                           \
    UCT_BXI_IFACE_GET_TX_DESC_ERR(_iface, _mp, _desc, _err)                    \
    UCT_BXI_IFACE_INIT_TX_DESC(_desc, _ep, _handler)                           \
    (_desc)->user_comp = _user_comp;                                           \
    *(_pack_length) =                                                          \
            _pack_cb(_iface, _desc + 1, _src, _len, _memh, _hdr, _hdrlen);     \
  })

#define UCT_BXI_IFACE_GET_TX_OP_COMP(_iface, _mp, _desc, _ep, _user_comp,      \
                                     _handler, _length)                        \
  UCT_BXI_IFACE_GET_TX_DESC(_iface, _mp, _desc)                                \
  UCT_BXI_IFACE_INIT_TX_DESC(_desc, _ep, _handler)                             \
  (_desc)->user_comp = _user_comp;                                             \
  UCT_SKIP_ZERO_LENGTH(_length, _desc);

#define UCT_BXI_IFACE_GET_TX_OP_COMP_ERR(_iface, _mp, _desc, _ep, _user_comp,  \
                                         _handler, _err)                       \
  UCT_BXI_IFACE_GET_TX_DESC_ERR(_iface, _mp, _desc, _err)                      \
  UCT_BXI_IFACE_INIT_TX_DESC(_desc, _ep, _handler)                             \
  (_desc)->user_comp = _user_comp;

/* For host memory: size of block is reduced by the payload size that 
 * is sent during the first control message of the sender, see 
 * uct_bxi_iface_tag_init to check how rndv_hdr_offset is computed. 
 * For cuda memory: we dont pack data into the control message to avoid 
 * gdr_copy latency. */
//TODO: We removed see TODO in uct_bxi_pack_rndv
// if (_mem_type == UCS_MEMORY_TYPE_HOST) {
//    (_desc)->start =
//            UCS_PTR_BYTE_OFFSET(_start, (_iface)->tm.rndv_hdr_offset);
//    (_desc)->size =
//            ucs_max((ssize_t)(_size - (_iface)->tm.rndv_hdr_offset), 0);
//  } else {

#define UCT_BXI_IFACE_GET_RX_RNDV_DESC(_iface, _mp, _desc, _mem_type, _start,  \
                                       _size, _cid, _cnt, _handler, _err_code) \
  UCT_TL_IFACE_GET_TX_DESC(&(_iface)->super, _mp, _desc, _err_code);           \
  (_desc)->start = _start;                                                     \
  (_desc)->size  = _size;                                                      \
  (_desc)->start = _start;                                                     \
  (_desc)->size  = _size;                                                      \
  UCT_BXI_RNDV_TAG_SET((_desc)->tag, (_cid).pti, (_cid).conn_key, _cnt);       \
  (_desc)->handler  = _handler;                                                \
  (_desc)->flags   |= UCT_BXI_RECV_BLOCK_FLAG_IN_USE;

#define UCT_BXI_IFACE_GET_RX_DESC(_iface, _mp, _desc, _mem_type, _orig,        \
                                  _start, _size, _tag, _ctx, _handler,         \
                                  _err_code)                                   \
  UCT_TL_IFACE_GET_TX_DESC(&(_iface)->super, _mp, _desc, _err_code);           \
  (_desc)->start     = _start;                                                 \
  (_desc)->orig      = _orig;                                                  \
  (_desc)->size      = _size;                                                  \
  (_desc)->tag       = _tag;                                                   \
  (_desc)->ctx       = _ctx;                                                   \
  (_desc)->handler   = _handler;                                               \
  (_desc)->mem_type  = _mem_type;                                              \
  (_desc)->flags    |= UCT_BXI_RECV_BLOCK_FLAG_IN_USE;

#endif
