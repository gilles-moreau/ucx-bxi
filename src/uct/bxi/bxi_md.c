#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "bxi.h"

#include "bxi_md.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

ucs_config_field_t uct_bxi_md_config_table[] = {
        {"", "", NULL, ucs_offsetof(uct_bxi_md_config_t, super),
         UCS_CONFIG_TYPE_TABLE(uct_md_config_table)},

        {"MAX_EVENTS", "65536",
         "Maximum number of events per event queue (default: 2048).",
         ucs_offsetof(uct_bxi_md_config_t, max_events), UCS_CONFIG_TYPE_UINT},

        {NULL}};

static const ptl_ni_limits_t default_limits = {
        .max_entries            = INT_MAX,
        .max_unexpected_headers = INT_MAX,
        .max_mds                = INT_MAX,
        .max_cts                = INT_MAX,
        .max_eqs                = INT_MAX,
        .max_pt_index           = INT_MAX,
        .max_iovecs             = INT_MAX,
        .max_list_size          = INT_MAX,
        .max_triggered_ops      = INT_MAX,
        .max_msg_size           = PTL_SIZE_MAX,
        .max_atomic_size        = PTL_SIZE_MAX,
        .max_fetch_atomic_size  = PTL_SIZE_MAX,
        .max_waw_ordered_size   = PTL_SIZE_MAX,
        .max_war_ordered_size   = PTL_SIZE_MAX,
        .max_volatile_size      = PTL_SIZE_MAX,
        .features               = 0,
};

ucs_status_t uct_bxi_md_mem_desc_create(uct_bxi_md_t             *md,
                                        uct_bxi_mem_desc_param_t *params,
                                        uct_bxi_mem_desc_t      **mem_desc_p)
{
  ucs_status_t        status;
  uct_bxi_mem_desc_t *mem_desc;
  ptl_md_t            ptl_md;

  if (params->flags & UCT_BXI_MEM_DESC_FLAG_ALLOCATE) {
    mem_desc = ucs_malloc(sizeof(uct_bxi_mem_desc_t), "mem_desc");
    if (mem_desc == NULL) {
      status = UCS_ERR_NO_MEMORY;
      goto err;
    }
    mem_desc->flags = UCT_BXI_MEM_DESC_FLAG_ALLOCATE;
  } else {
    /* Memory has already been allocate during memory 
     * pool initialization. */
    mem_desc = *mem_desc_p;
  }

  status = uct_ptl_wrap(PtlCTAlloc(md->nih, &mem_desc->cth));
  if (status != UCS_OK) {
    goto err_free_memdesc;
  }

  ptl_md = (ptl_md_t){
          .start     = params->start,
          .length    = params->length,
          .ct_handle = mem_desc->cth,
          .eq_handle = params->eqh,
          .options   = params->options,
  };

  status = uct_ptl_wrap(PtlMDBind(md->nih, &ptl_md, &mem_desc->mdh));
  if (status != UCS_OK) {
    goto err_clean_ct;
  }

  ucs_queue_head_init(&mem_desc->send_ops);

  *mem_desc_p = mem_desc;

  return status;

err_clean_ct:
  uct_bxi_wrap(PtlCTFree(mem_desc->cth));
err_free_memdesc:
  /* Only free if it was manually allocated. */
  if (mem_desc->flags & UCT_BXI_MEM_DESC_FLAG_ALLOCATED) {
    ucs_free(mem_desc);
  }
err:
  return status;
}

void uct_bxi_md_mem_desc_fini(uct_bxi_mem_desc_t *mem_desc)
{
  /* There must not be any outstanding operations when deleting the 
   * Memory Descriptor. */
  ucs_assert(ucs_queue_is_empty(&mem_desc->send_ops));

  /* Then free Portals resources. */
  uct_bxi_wrap(PtlCTFree(mem_desc->cth));

  uct_bxi_wrap(PtlMDRelease(mem_desc->mdh));

  if (mem_desc->flags & UCT_BXI_MEM_DESC_FLAG_ALLOCATED) {
    ucs_free(mem_desc);
  }
}

ucs_status_t uct_bxi_mem_reg(uct_md_h uct_md, void *address, size_t length,
                             const uct_md_mem_reg_params_t *params,
                             uct_mem_h                     *memh_p)
{
  *memh_p = (void *)0xdeadbeef;
  return UCS_OK;
}

ucs_status_t uct_bxi_mem_dereg(uct_md_h                         uct_md,
                               const uct_md_mem_dereg_params_t *params)
{
  ucs_assert(params->memh == (void *)0xdeadbeef);
  return UCS_OK;
}

ucs_status_t uct_bxi_rkey_unpack(uct_component_t *component,
                                 const void *rkey_buffer, uct_rkey_t *rkey_p,
                                 void **handle_p)
{
  *rkey_p   = 0;
  *handle_p = NULL;
  return UCS_OK;
}

ucs_status_t uct_bxi_md_query(uct_md_h uct_md, uct_md_attr_v2_t *md_attr)
{
  uct_bxi_md_t *md                    = ucs_derived_of(uct_md, uct_bxi_md_t);
  size_t        component_name_length = strlen(md->super.component->name);

  uct_md_base_md_query(md_attr);
  md_attr->max_alloc = ULONG_MAX;
  md_attr->max_reg   = ULONG_MAX;
  md_attr->flags =
          UCT_MD_FLAG_REG | UCT_MD_FLAG_NEED_MEMH | UCT_MD_FLAG_NEED_RKEY;
  md_attr->access_mem_types       = UCS_BIT(UCS_MEMORY_TYPE_HOST);
  md_attr->reg_mem_types          = UCS_BIT(UCS_MEMORY_TYPE_HOST);
  md_attr->gva_mem_types          = 0;
  md_attr->reg_nonblock_mem_types = UCS_BIT(UCS_MEMORY_TYPE_HOST);
  md_attr->cache_mem_types        = UCS_BIT(UCS_MEMORY_TYPE_HOST);
  md_attr->access_mem_types       = UCS_BIT(UCS_MEMORY_TYPE_HOST);
  md_attr->rkey_packed_size       = 0;
  md_attr->reg_cost               = ucs_linear_func_make(9e-9, 0);

  memcpy(md_attr->global_id, md->super.component->name, component_name_length);

  return UCS_OK;
}

// FIXME: different NET interface needs to be given a unique ptl_interface_t
// value.
static inline ptl_interface_t uct_bxi_parse_device(const char *ptl_device)
{
  ptl_interface_t iface;
  if (strstr(ptl_device, "bxi") == NULL) {
    // Device name from simulator, thus return 0
    iface = 0;
  } else {
    sscanf(UCS_PTR_TYPE_OFFSET(ptl_device, 3), "%d", &iface);
  }
  return iface;
}

ucs_status_t uct_bxi_query_md_resources(uct_component_t         *component,
                                        uct_md_resource_desc_t **resources_p,
                                        unsigned *num_resources_p)
{
  int                     rc         = UCS_OK;
  static const char      *bxi_dir[2] = {"/sys/class/bxi", "/sys/class/net"};
  uct_md_resource_desc_t *resources;
  int                     i = 0;
  int                     is_up;
  int                     num_devices;
  struct dirent          *entry;
  DIR                    *dir;

  resources   = NULL;
  num_devices = 0;

  /* Check if bxi are available in with sysfs */
  do {
    dir = opendir(bxi_dir[i]);
    if (dir == NULL) {
      ucs_debug("PTL: could not open bxi directory %s.", bxi_dir[i]);
      continue;
    }

    for (;;) {
      errno = 0;
      entry = readdir(dir);
      if (entry == NULL) {
        if (errno != 0) {
          ucs_error("PTL: could not read bxi directory %s.", bxi_dir[i]);
          rc = UCS_ERR_NO_MEMORY;
          goto close_dir;
        }
        break;
      }

      /* avoid reading entry like . and .. */
      if (entry->d_type != DT_LNK) {
        continue;
      }

      is_up = 1;
      // TODO: check if interface is up with bixnic -i <iface> info
      //       LINK_STATUS
      if (!is_up) {
        continue;
      }

      resources = realloc(resources, sizeof(*resources) * (num_devices + 1));
      if (resources == NULL) {
        ucs_error("PTL: could not allocate devices");
        rc = UCS_ERR_NO_MEMORY;
        goto close_dir;
      }

      strcpy(resources[num_devices].md_name, entry->d_name);
      ++num_devices;
      if (i == 1)
        break;
    }

  close_dir:
    closedir(dir);
  } while (num_devices == 0 && ++i < 2);

  *resources_p     = resources;
  *num_resources_p = num_devices;

  return rc;
}

void uct_bxi_md_close(uct_md_h uct_md)
{
  uct_bxi_md_t *md = ucs_derived_of(uct_md, uct_bxi_md_t);

  uct_bxi_wrap(PtlNIFini(md->nih));

  ucs_free(md->device);

  ucs_free(md);
}

static inline void uct_bxi_md_config_init(uct_bxi_md_t              *md,
                                          const uct_bxi_md_config_t *md_config)
{
  return;
}

static uct_md_ops_t uct_bxi_md_ops = {
        .close              = uct_bxi_md_close,
        .query              = uct_bxi_md_query,
        .mem_reg            = uct_bxi_mem_reg,
        .mem_dereg          = uct_bxi_mem_dereg,
        .mem_attach         = ucs_empty_function_return_unsupported,
        .mem_advise         = ucs_empty_function_return_unsupported,
        .mkey_pack          = ucs_empty_function_return_success,
        .detect_memory_type = ucs_empty_function_return_unsupported,
};

static ucs_status_t uct_bxi_md_open(uct_component_t       *component,
                                    const char            *md_name,
                                    const uct_md_config_t *uct_md_config,
                                    uct_md_h              *md_p)
{
  ucs_status_t               rc = UCS_OK;
  uct_bxi_md_t              *md;
  const uct_bxi_md_config_t *md_config =
          ucs_derived_of(uct_md_config, uct_bxi_md_config_t);

  md = ucs_calloc(1, sizeof(*md), "bxi-md");
  if (md == NULL) {
    ucs_error("failed to allocate memory for md");
    goto err;
  }

  uct_bxi_md_config_init(md, md_config);

  /* init one physical interface */
  rc = uct_bxi_wrap(PtlNIInit(uct_bxi_parse_device(md_name),
                              PTL_NI_MATCHING | PTL_NI_PHYSICAL, PTL_PID_ANY,
                              &default_limits, &md->config.limits, &md->nih));
  if (rc != UCS_OK) {
    goto err_free_md;
  }

  md->device = ucs_strdup(md_name, "md-name-dup");
  if (md->device == NULL) {
    ucs_error("PTL: Could not allocate bxi device name");
    rc = UCS_ERR_NO_MEMORY;
    goto err_nifini;
  }

  /* retrieve the process identifier */
  rc = uct_bxi_wrap(PtlGetPhysId(md->nih, &md->pid));
  if (rc != UCS_OK) {
    goto err_freedev;
  }

  md->super.ops       = &uct_bxi_md_ops;
  md->super.component = component;

  *md_p = &md->super;

  return rc;

err_freedev:
  ucs_free(md->device);
err_nifini:
  PtlNIFini(md->nih);
err_free_md:
  ucs_free(md);
err:
  return rc;
}

uct_component_t uct_bxi_component = {
        .query_md_resources = uct_bxi_query_md_resources,
        .md_open            = uct_bxi_md_open,
        .cm_open            = ucs_empty_function_return_unsupported,
        .rkey_unpack        = uct_bxi_rkey_unpack,
        .rkey_ptr           = ucs_empty_function_return_unsupported,
        .rkey_release       = ucs_empty_function_return_success,
        .rkey_compare       = uct_base_rkey_compare,
        .name               = "bxi",
        .md_config =
                {
                        .name   = "BXI memory domain",
                        .prefix = UCT_BXI_CONFIG_PREFIX,
                        .table  = uct_bxi_md_config_table,
                        .size   = sizeof(uct_bxi_md_config_t),
                },
        .cm_config   = UCS_CONFIG_EMPTY_GLOBAL_LIST_ENTRY,
        .tl_list     = UCT_COMPONENT_TL_LIST_INITIALIZER(&uct_bxi_component),
        .flags       = 0,
        .md_vfs_init = (uct_component_md_vfs_init_func_t)ucs_empty_function,
};
