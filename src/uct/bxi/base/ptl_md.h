#ifndef PTL_MD_H
#define PTL_MD_H

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>
#include <uct/bxi/ptl_types.h>

#define UCT_PTL_CONFIG_PREFIX "PTL_"

enum {
  UCT_PTL_MR_FLAGS_INITIATOR = UCS_BIT(0),
  UCT_PTL_MR_FLAGS_TARGET = UCS_BIT(1),
};

enum {
  UCT_PTL_MEM_FLAG_ODP = UCS_BIT(0),             /**< The memory region has on
                                                     demand paging enabled */
  UCT_PTL_MEM_ACCESS_REMOTE_ATOMIC = UCS_BIT(1), /**< An atomic access was
                                                     requested for the memory
                                                     region */
  UCT_PTL_MEM_MULTITHREADED = UCS_BIT(2), /**< The memory region registration
                                              handled by chunks in parallel
                                              threads */
  UCT_PTL_MEM_IMPORTED = UCS_BIT(3),      /**< The memory handle was
                                              created by mem_attach */
#if ENABLE_PARAMS_CHECK
  UCT_PTL_MEM_ACCESS_REMOTE_RMA = UCS_BIT(4), /**< RMA access was requested
                                                  for the memory region */
#else
  UCT_IB_MEM_ACCESS_REMOTE_RMA = 0,
#endif
};

typedef struct uct_ptl_rkey {
  char dummy;
} uct_ptl_rkey_t;

typedef struct uct_ptl_mmd_param {
  unsigned flags;
} uct_ptl_mmd_param_t;

typedef struct uct_ptl_mmd {
  ucs_list_link_t elem;
  ptl_handle_md_t mdh;
  ptl_handle_ct_t cth;
  ucs_queue_head_t opq;
  ptl_ct_event_t p_cnt;
  ptl_size_t seqn;
} uct_ptl_mmd_t;

typedef struct uct_ptl_me_param {
  unsigned flags;
  void *start;
  ptl_size_t length;
  ptl_match_bits_t match;
  ptl_match_bits_t ign;
} uct_ptl_me_param_t;

typedef struct uct_ptl_me {
  ptl_handle_me_t meh;
  ptl_match_bits_t match;
  uint64_t offset;
} uct_ptl_me_t;

typedef struct uct_ptl_mr {
  unsigned flags;
} uct_ptl_mr_t;

typedef struct uct_ptl_md_config {
  uct_md_config_t super;
} uct_ptl_md_config_t;

extern ucs_config_field_t uct_ptl_md_config_table[];

typedef struct uct_ptl_md {
  uct_md_t super;
  struct {
    int id;
  } config;
  char *device;
  ptl_handle_ni_t nih;
  ptl_process_t pid;
  ptl_ni_limits_t limits;
  ptl_pt_index_t pti;
  uint64_t cap_flags;
  size_t rkey_size;
} uct_ptl_md_t;

ucs_status_t uct_ptl_md_mdesc_init(uct_ptl_md_t *md, uct_ptl_mmd_param_t *param,
                                   uct_ptl_mmd_t *mmd);
ucs_status_t uct_ptl_md_mdesc_fini(uct_ptl_mmd_t *mmd);
ucs_status_t uct_ptl_md_me_init(uct_ptl_md_t *md, uct_ptl_me_param_t *param,
                                uct_ptl_me_t *me);
ucs_status_t uct_ptl_md_me_fini(uct_ptl_md_t *md, uct_ptl_me_t *me);
uct_ptl_md_t *uct_ptl_md_alloc(size_t size, const char *name);
ucs_status_t uct_ptl_md_init(uct_ptl_md_t *md, const char *ptl_device,
                             const uct_ptl_md_config_t *config);
ucs_status_t uct_ptl_md_query(uct_md_h uct_md, uct_md_attr_v2_t *md_attr);
void uct_ptl_md_close(uct_ptl_md_t *md);
ucs_status_t uct_ptl_query_md_resources(uct_component_t *component,
                                        uct_md_resource_desc_t **resources_p,
                                        unsigned *num_resources_p);

/**
 * Memory domain constructor.
 *
 * @param [in]  ptl_device    PTL device.
 *
 * @param [in]  md_config     Memory domain configuration parameters.
 *
 * @param [out] md_p          Handle to memory domain.
 *
 * @return UCS_OK on success or error code in case of failure.
 */
typedef ucs_status_t (*uct_ptl_md_open_func_t)(
    const char *ptl_device, const uct_ptl_md_config_t *md_config,
    struct uct_ptl_md **md_p);

typedef struct uct_ptl_md_ops {
  uct_md_ops_t super;
} uct_ptl_md_ops_t;

typedef struct uct_ptl_md_ops_entry {
  ucs_list_link_t list;
  const char *name;
  uct_ptl_md_ops_t *ops;
} uct_ptl_md_ops_entry_t;

#endif
