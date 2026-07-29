#ifndef BXI_MD_H
#define BXI_MD_H

#include "bxi.h"

#ifdef HAVE_GDR_COPY
#include "gdrapi.h"
#endif

#include <uct/base/uct_iface.h>
#include <uct/base/uct_md.h>

#define UCT_BXI_CONFIG_PREFIX "BXI_"

enum {
  UCT_BXI_MEM_DESC_FLAG_ALLOCATE  = UCS_BIT(0),
  UCT_BXI_MEM_DESC_FLAG_ALLOCATED = UCS_BIT(1),
};

/**
 * @brief bxi mem handle
 */
typedef struct uct_bxi_mem {
#ifdef HAVE_GDR_COPY
  gdr_mh_t   mh;   /**< Memory handle of GPU memory */
  gdr_info_t info; /**< Info of GPU memory mapping */
#endif
  void  *bar_ptr;  /**< BAR address of GPU mapping */
  size_t reg_size; /**< Size of mapping */
  size_t offset;   /**< Offset of origin address after alignment */
} uct_bxi_mem_t;

/**
 * @brief bxi  packed and remote key for put
 */
typedef struct uct_bxi_rkey {
  uint64_t vaddr;   /**< Mapped GPU address */
  void    *bar_ptr; /**< BAR address of GPU mapping */
} uct_bxi_rkey_t;

typedef struct uct_bxi_md_config {
  uct_md_config_t super;
  size_t          max_events;
  int             enable_gpudirect_rdma; /**< Enable GPUDirect RDMA */
} uct_bxi_md_config_t;

extern ucs_config_field_t uct_bxi_md_config_table[];

typedef struct uct_bxi_md {
  uct_md_t super;
  struct {
    ptl_ni_limits_t limits;
  } config;
  char             *device;
  ucs_sys_device_t  sys_dev;
  ptl_handle_ni_t   nih;
  ptl_process_t     pid;
  size_t            rkey_size;
  uint64_t          reg_mem_types;
  ucs_linear_func_t reg_cost;              /**< Memory registration cost */
  int               enable_gpudirect_rdma; /**< Enable GPUDirect RDMA */
#ifdef HAVE_GDR_COPY
  gdr_t gdrcpy_ctx;
#endif
} uct_bxi_md_t;

ucs_status_t uct_bxi_md_query(uct_md_h uct_md, uct_md_attr_v2_t *md_attr);
ucs_status_t uct_bxi_query_md_resources(uct_component_t         *component,
                                        uct_md_resource_desc_t **resources_p,
                                        unsigned *num_resources_p);

ucs_status_t uct_bxi_mkey_pack(uct_md_h uct_md, uct_mem_h uct_memh,
                               void *address, size_t length,
                               const uct_md_mkey_pack_params_t *params,
                               void                            *buffer);

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
