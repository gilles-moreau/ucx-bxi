#ifndef BXI_IFACE_H
#define BXI_IFACE_H

#include "bxi_md.h"
#include "bxi_rxq.h"

#include <ucs/type/status.h>
#include <uct/base/uct_iface.h>
#include <uct/bxi/ptl_types.h>
#include <unistd.h>

enum {
  UCT_ERR_BXI_CT_FAILURE = UCS_ERR_FIRST_ENDPOINT_FAILURE,
};

typedef struct uct_bxi_iface         uct_bxi_iface_t;
typedef struct uct_bxi_iface_send_op uct_bxi_iface_send_op_t;
typedef struct uct_bxi_ep            uct_bxi_ep_t;

typedef void (*handle_failure_func_t)(uct_bxi_iface_t         *iface,
                                      uct_bxi_iface_send_op_t *op,
                                      ptl_ni_fail_t            fail);

typedef void (*uct_bxi_send_handler_t)(uct_bxi_iface_send_op_t *op,
                                       const void              *resp);

typedef struct uct_bxi_iface_addr {
  ptl_pt_index_t am;
  ptl_pt_index_t rma;
  ptl_pt_index_t tag;
} uct_bxi_iface_addr_t;

typedef struct uct_bxi_ep_addr {
  uct_bxi_iface_addr_t iface_addr;
} uct_bxi_ep_addr_t;

typedef struct uct_bxi_iface_txq {
  uct_bxi_mem_desc_t mem_desc; /* Memory Descriptor */
  ucs_list_link_t    elem;     /* Element in the list of TX to poll */
  ucs_queue_head_t   op_q;     /* Queue of outstanding operations */
  uint64_t           sn;       /* TX Queue sequence number */
} uct_bxi_iface_txq_t;

typedef struct uct_bxi_iface_send_op {
  unsigned          flags;
  ucs_queue_elem_t  elem;      /* Element on a TX queue */
  uct_completion_t *user_comp; /* Completion callback */
  uct_bxi_ep_t     *ep;        /* OP endpoint */
  ptl_size_t        sn;        /* OP sequence number */
} uct_bxi_iface_send_op_t;

typedef struct uct_bxi_op_ctx {
  uct_oop_ctx_t   super;
  ptl_handle_ct_t cth;
  ptl_size_t      threshold;
} uct_bxi_op_ctx_t;

typedef struct uct_bxi_device_addr {
  ptl_process_t pid;
} uct_bxi_device_addr_t;

typedef struct uct_bxi_iface_ops {
  uct_iface_internal_ops_t super;
  handle_failure_func_t    handle_failure;
} uct_bxi_iface_ops_t;

typedef struct uct_bxi_iface_config {
  uct_iface_config_t super;
  size_t             max_events;
  int                seg_size; /* Max copy-out size of send buffers */

  struct {
    int max_queue_len; /* Maximum number of outstanding OP */
    uct_iface_mpool_config_t mp;
  } tx;

  struct {
    int max_queue_len;    /* Maximum number of receive descriptor in the RXQ. */
    int eager_block_size; /* Receive block size within the memory pool. */
    uct_iface_mpool_config_t am_mp;  /* Receive descriptor for AM RX. */
    uct_iface_mpool_config_t tag_mp; /* Receive descriptor for TAG RX. */
  } rx;

  int      max_ep_retries;
  int      copyin_buf_per_block;
  int      copyout_buf_per_block;
  int      min_copyin_buf;
  int      max_copyin_buf;
  int      max_copyout_buf;
  unsigned features;
  struct {
    int          enable;
    unsigned int list_size;
    unsigned int max_op_ctx;
  } tm;
} uct_bxi_iface_config_t;

#define uct_bxi_tag_addr_hash(_ptr) kh_int64_hash_func((uintptr_t)(_ptr))
KHASH_INIT(uct_bxi_tag_addrs, void *, char, 0, uct_bxi_tag_addr_hash,
           kh_int64_hash_equal)

typedef struct uct_bxi_iface {
  uct_base_iface_t super;
  struct {
    struct {
      int seg_size;
      int max_copyin_buf;
    } tx;

    struct {
      int num_eager_blocks;
      int eager_block_size;
    } rx;

    size_t   max_events;
    int      max_ep_retries;
    int      max_outstanding_ops;
    int      copyout_buf_per_block;
    int      max_copyout_buf;
    int      max_iovecs;
    int      max_short;
    size_t   max_msg_size;
    size_t   max_atomic_size;
    unsigned features;
    size_t   iface_addr_size;
    size_t   device_addr_size;
    size_t   ep_addr_size;
    struct {
      unsigned int max_op_ctx;
      unsigned int max_tags;
    } tm;
  } config;

  struct {
    unsigned int               enabled;
    unsigned int               num_outstanding;
    unsigned int               unexpected_cnt;
    unsigned int               num_tags;
    unsigned int               num_op_ctx;
    khash_t(uct_bxi_tag_addrs) tag_addrs;
    struct {
      void                    *arg; /* User defined arg */
      uct_tag_unexp_eager_cb_t cb;  /* Callback for unexpected eager messages */
    } eager_unexp;
    struct {
      void                   *arg; /* User defined arg */
      uct_tag_unexp_rndv_cb_t cb;  /* Callback for unexpected rndv messages */
    } rndv_unexp;
    ucs_mpool_t  recv_ops_mp;
    unsigned int recv_tried_offload;
  } tm;

  struct {
    ucs_mpool_t      send_desc_mp; /* Memory pool of send descriptor */
    ucs_mpool_t      send_op_mp;   /* Memory pool of send operations */
    ucs_mpool_t      flush_ops_mp; /* Memory pool for flush OP */
    ucs_list_link_t  tx_queues;    /* List of TX Queues */
    ucs_queue_head_t pending_q;    /* List of pending OP */
  } tx;

  struct {
    ptl_handle_eq_t eqh;
    struct {
      uct_bxi_rxq_t *rxq;
    } am;
    struct {
      uct_bxi_rxq_t *rxq;
    } tag;
    struct {
      ptl_pt_index_t      pti;
      uct_bxi_mem_entry_t entry;
    } rma;
  } rx;

  uct_bxi_md_t *md;
} uct_bxi_iface_t;

UCS_CLASS_DECLARE(uct_bxi_iface_t, uct_iface_ops_t *, uct_bxi_iface_ops_t *,
                  uct_md_h, uct_worker_h, const uct_iface_params_t *,
                  const uct_bxi_iface_config_t *);

static inline int uct_bxi_iface_cmp_device_addr(uct_bxi_device_addr_t *dev1,
                                                uct_bxi_device_addr_t *dev2)
{
  return dev1->pid.phys.pid == dev2->pid.phys.nid &&
         dev1->pid.phys.nid == dev2->pid.phys.nid;
}

extern ucs_config_field_t uct_bxi_iface_common_config_table[];
extern ucs_config_field_t uct_bxi_iface_config_table[];
extern char              *uct_bxi_event_str[];

// FIXME: this triggers a clang include not used error, check other solution
#define uct_bxi_iface_md(_iface)                                               \
  (ucs_derived_of((_iface)->super.md, uct_bxi_md_t))

#endif
