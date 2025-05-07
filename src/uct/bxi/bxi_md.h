#ifndef BXI_MD_H
#define BXI_MD_H

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>

#include <uct/bxi/ptl_types.h>

#define UCT_BXI_CONFIG_PREFIX "BXI_"

enum {
  UCT_BXI_MEM_DESC_FLAG_ALLOCATE  = UCS_BIT(0),
  UCT_BXI_MEM_DESC_FLAG_ALLOCATED = UCS_BIT(1),
};

typedef struct uct_bxi_rkey {
  char dummy;
} uct_bxi_rkey_t;

typedef struct uct_bxi_mem_desc_param {
  unsigned        options;
  unsigned        flags;
  ptl_handle_eq_t eqh;
  void           *start;
  ptl_size_t      length;
  ptl_handle_ct_t cth;
} uct_bxi_mem_desc_param_t;

typedef struct uct_bxi_mem_desc {
  unsigned        flags;
  ptl_handle_md_t mdh; /* Portals4 MD handle */
  uint64_t        sn;  /* Current sequence number
                       //FIXME: review sn ownership (iface, ep,...) */
} uct_bxi_mem_desc_t;

typedef struct uct_bxi_mem_entry_param {
  unsigned         options;
  void            *start;
  ptl_size_t       length;
  ptl_match_bits_t match;
  ptl_match_bits_t ign;
} uct_bxi_mem_entry_param_t;

typedef struct uct_bxi_mem_entry {
  ptl_handle_me_t meh;
} uct_bxi_mem_entry_t;

typedef struct uct_bxi_md_config {
  uct_md_config_t super;
  size_t          max_events;
} uct_bxi_md_config_t;

extern ucs_config_field_t uct_bxi_md_config_table[];

typedef struct uct_bxi_md {
  uct_md_t super;
  struct {
    ptl_ni_limits_t limits;
  } config;
  char           *device;
  ptl_handle_ni_t nih;
  ptl_process_t   pid;
  size_t          rkey_size;
} uct_bxi_md_t;

ucs_status_t uct_bxi_md_query(uct_md_h uct_md, uct_md_attr_v2_t *md_attr);
ucs_status_t uct_bxi_query_md_resources(uct_component_t         *component,
                                        uct_md_resource_desc_t **resources_p,
                                        unsigned *num_resources_p);

ucs_status_t uct_bxi_md_mem_desc_create(uct_bxi_md_t             *md,
                                        uct_bxi_mem_desc_param_t *params,
                                        uct_bxi_mem_desc_t      **mem_desc_p);
void         uct_bxi_md_mem_desc_fini(uct_bxi_mem_desc_t *mem_desc);
/**
 * Memory domain constructor.
 *
 * @param [in]  ptl_device    BXI device.
 *
 * @param [in]  md_config     Memory domain configuration parameters.
 *
 * @param [out] md_p          Handle to memory domain.
 *
 * @return UCS_OK on success or error code in case of failure.
 */
typedef ucs_status_t (*uct_bxi_md_open_func_t)(
        const char *ptl_device, const uct_bxi_md_config_t *md_config,
        struct uct_bxi_md **md_p);

typedef struct uct_bxi_md_ops {
  uct_md_ops_t super;
} uct_bxi_md_ops_t;

typedef struct uct_bxi_md_ops_entry {
  ucs_list_link_t   list;
  const char       *name;
  uct_bxi_md_ops_t *ops;
} uct_bxi_md_ops_entry_t;

#endif
