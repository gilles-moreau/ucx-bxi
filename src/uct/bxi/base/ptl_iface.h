#ifndef PTL_IFACE_H
#define PTL_IFACE_H

#include "ptl_md.h"
#include "ucs/type/status.h"

#include <uct/base/uct_iface.h>
#include <uct/bxi/ptl_types.h>
#include <unistd.h>

enum {
  UCT_ERR_PTL_CT_FAILURE = UCS_ERR_FIRST_ENDPOINT_FAILURE,
};

typedef ucs_status_t (*handle_ev_func_t)(uct_ptl_iface_t *iface,
                                         ptl_event_t *ev);

typedef ucs_status_t (*cancel_ops_func_t)(uct_ptl_iface_t *iface);

typedef void (*handle_failure_func_t)(uct_ptl_iface_t *iface, uct_ptl_op_t *op,
                                      ptl_ni_fail_t fail);

typedef struct uct_ptl_device_addr {
  ptl_process_t pid;
} uct_ptl_device_addr_t;

typedef struct uct_ptl_ep_addr {
  uct_ptl_device_addr_t dev_addr;
} uct_ptl_ep_addr_t;

typedef struct uct_ptl_iface_ops {
  uct_iface_internal_ops_t super;
  handle_ev_func_t handle_ev;
  cancel_ops_func_t cancel_ops;
  handle_failure_func_t handle_failure;
} uct_ptl_iface_ops_t;

typedef struct uct_ptl_iface_config {
  uct_iface_config_t super;
  size_t max_events;
  int max_ep_retries;
  int max_outstanding_ops;
  int copyin_buf_per_block;
  int copyout_buf_per_block;
  int min_copyin_buf;
  int max_copyin_buf;
  int max_copyout_buf;
  int num_eager_blocks;
  int eager_block_size;
  unsigned features;
} uct_ptl_iface_config_t;

typedef struct uct_ptl_iface {
  uct_base_iface_t super;
  struct {
    size_t max_events;
    int max_ep_retries;
    int max_outstanding_ops;
    int copyin_buf_per_block;
    int min_copyin_buf;
    int max_copyin_buf;
    int copyout_buf_per_block;
    int max_copyout_buf;
    int num_eager_blocks;
    int max_iovecs;
    int max_short;
    size_t eager_block_size;
    size_t max_msg_size;
    size_t max_atomic_size;
    ptl_ni_limits_t limits;
    unsigned features;
    size_t iface_addr_size;
    size_t device_addr_size;
    size_t ep_addr_size;
  } config;
  uct_ptl_iface_ops_t ops;
  ucs_list_link_t mds; // Memory descriptors
  ucs_mpool_t ops_mp;
  ucs_mpool_t flush_ops_mp;
  ucs_mpool_t copyin_mp;
  ucs_queue_head_t pending_q;
} uct_ptl_iface_t;

UCS_CLASS_DECLARE(uct_ptl_iface_t, uct_iface_ops_t *, uct_ptl_iface_ops_t *,
                  uct_md_h, uct_worker_h, const uct_iface_params_t *,
                  const uct_ptl_iface_config_t *);

extern ucs_config_field_t uct_ptl_iface_config_table[];
extern ucs_config_field_t uct_ptl_iface_common_config_table[];

// FIXME: use UCX INLINE MACROS
static inline int uct_ptl_iface_cmp_device_addr(uct_ptl_device_addr_t *dev1,
                                                uct_ptl_device_addr_t *dev2) {
  return dev1->pid.phys.pid == dev2->pid.phys.nid &&
         dev1->pid.phys.nid == dev2->pid.phys.nid;
}

ucs_status_t uct_ptl_query_devices(uct_md_h component,
                                   uct_tl_resource_desc_t **resources_p,
                                   unsigned *num_resources_p);
unsigned uct_ptl_iface_progress(uct_iface_t *super);
ucs_status_t uct_ptl_iface_get_device_address(uct_iface_h tl_iface,
                                              uct_device_addr_t *tl_addr);
ucs_status_t uct_ptl_iface_query(uct_iface_t *iface, uct_iface_attr_t *attr);
int uct_ptl_md_progress(uct_ptl_mmd_t *mmd);

ucs_status_t
uct_ptl_iface_query_tl_devices(uct_md_h md,
                               uct_tl_device_resource_t **tl_devices_p,
                               unsigned *num_tl_devices_p);

static inline void uct_ptl_iface_enable_progression(uct_ptl_iface_t *iface,
                                                    uct_ptl_mmd_t *mmd) {
  ucs_list_add_head(&iface->mds, &mmd->elem);
}

static inline void uct_ptl_iface_disable_progression(uct_ptl_mmd_t *mmd) {
  ucs_list_del(&mmd->elem);
}

ucs_status_t uct_ptl_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                 uct_completion_t *comp);

ucs_status_t uct_ptl_iface_fence(uct_iface_h tl_iface, unsigned flags);

extern ucs_config_field_t uct_ptl_iface_config_table[];
extern char *uct_ptl_event_str[];

// FIXME: this triggers a clang include not used error, check other solution
#define uct_ptl_iface_md(_iface)                                               \
  (ucs_derived_of((_iface)->super.md, uct_ptl_md_t))

#endif
