#ifndef PTL_MD_H
#define PTL_MD_H

#include <uct/base/uct_md.h>
#include <uct/bxi/ptl_types.h>

enum {
  ECR_PTL_MR_FLAGS_INITIATOR = UCS_BIT(0),
  ECR_PTL_MR_FLAGS_TARGET = UCS_BIT(1),
};

typedef struct uct_ptl_rkey {
  char dummy;
} uct_ptl_rkey_t;

typedef struct uct_ptl_mmd_param {
  unsigned flags;
} uct_ptl_md_param_t;

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
  ptl_pt_index_t idx;
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
  ptl_handle_ni_t nih;
  ptl_process_t pid;
  ptl_ni_limits_t limits;
  ptl_pt_index_t pti;
} uct_ptl_md_t;

ucs_status_t uct_ptl_md_md_init(uct_ptl_md_t *md, uct_ptl_md_param_t *param,
                                uct_ptl_mmd_t *mmd);
ucs_status_t uct_ptl_md_md_fini(uct_ptl_mmd_t *mmd);
ucs_status_t uct_ptl_md_me_init(uct_ptl_md_t *md, uct_ptl_me_param_t *param,
                                uct_ptl_me_t *me);
ucs_status_t uct_ptl_md_me_fini(uct_ptl_md_t *md, uct_ptl_me_t *me);

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
  uct_ptl_md_open_func_t open;
} uct_ptl_md_ops_t;

typedef struct uct_ptl_md_ops_entry {
  ucs_list_link_t list;
  const char *name;
  uct_ptl_md_ops_t *ops;
} uct_ptl_md_ops_entry_t;

#define UCT_PTL_MD_OPS_NAME(_name) uct_ptl_md_ops_##_name##_entry

#define UCT_PTL_MD_DEFINE_ENTRY(_name, _md_ops)                                \
  uct_ptl_md_ops_entry_t UCT_PTL_MD_OPS_NAME(_name) = {                        \
      .name = UCS_PP_MAKE_STRING(_md_ops),                                     \
      .ops = &_md_ops,                                                         \
  }
#endif
