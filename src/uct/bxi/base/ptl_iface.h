#ifndef PTL_IFACE_H
#define PTL_IFACE_H

#include "ptl_md.h"

#include <uct/base/uct_iface.h>
#include <uct/bxi/ptl_types.h>

typedef ucs_status_t (*handle_ev_func_t)(uct_ptl_iface_t *iface,
                                         ptl_event_t *ev);

typedef struct uct_ptl_iface_addr {
  ptl_process_t pid;
} uct_ptl_iface_addr_t;

typedef struct uct_ptl_iface_ops {
  uct_iface_internal_ops_t super;
  handle_ev_func_t handle_ev;
} uct_ptl_iface_ops_t;

typedef struct uct_ptl_iface_config {
  uct_iface_config_t super;
  size_t max_events;
  int max_outstanding_ops;
  int copyin_buf_per_block;
  int min_copyin_buf;
  int max_copyin_buf;
  int num_eager_blocks;
  int eager_block_size;
  unsigned features;
} uct_ptl_iface_config_t;

typedef struct uct_ptl_iface {
  uct_base_iface_t super;
  struct {
    size_t max_events;
    int max_outstanding_ops;
    int copyin_buf_per_block;
    int min_copyin_buf;
    int max_copyin_buf;
    int num_eager_blocks;
    int max_iovecs;
    int max_short;
    size_t eager_block_size;
    size_t max_msg_size;
    size_t max_atomic_size;
    ptl_ni_limits_t limits;
    unsigned features;
    size_t iface_addr_size;
  } config;
  uct_ptl_iface_ops_t ops;
  ptl_handle_eq_t eqh; // Event Queue
  ucs_list_link_t mds; // Memory descriptors
} uct_ptl_iface_t;

UCS_CLASS_DECLARE(uct_ptl_iface_t, uct_iface_ops_t *, uct_ptl_iface_ops_t *,
                  uct_md_h, uct_worker_h, const uct_iface_params_t *,
                  const uct_ptl_iface_config_t *);

extern ucs_config_field_t uct_ptl_iface_config_table[];
extern ucs_config_field_t uct_ptl_iface_common_config_table[];

ucs_status_t uct_ptl_query_devices(uct_md_h component,
                                   uct_tl_resource_desc_t **resources_p,
                                   unsigned *num_resources_p);
ucs_status_t uct_ptl_iface_progress(uct_iface_h super);
void uct_ptl_iface_get_attr(uct_iface_h iface, uct_iface_attr_t *attr);
ucs_status_t uct_ptl_md_progress(uct_ptl_mmd_t *mmd);

static inline void uct_ptl_iface_enable_progression(uct_ptl_iface_t *iface,
                                                    uct_ptl_mmd_t *mmd) {
  ucs_list_add_head(&iface->mds, &mmd->elem);
}

static inline void uct_ptl_iface_disable_progression(uct_ptl_mmd_t *mmd) {
  ucs_list_del(&mmd->elem);
}

extern ucs_config_field_t uct_ptl_iface_config_table[];
extern char *uct_ptl_event_str[];

// FIXME: this triggers a clang include not used error, check other solution
#define uct_ptl_iface_md(_iface)                                               \
  (ucs_derived_of((_iface)->super.md, uct_ptl_md_t))

#endif
