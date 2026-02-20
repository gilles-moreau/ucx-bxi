#include <omp.h>
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "bxi_md.h"

#include "bxi.h"
#include <ucs/memory/memtype_cache.h>
#include <ucs/sys/string.h>

#ifdef HAVE_GDR_COPY
#include <ucs/sys/ptr_arith.h>
#endif

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

#define UCT_BXI_MD_NETDEV_DIR "/sys/class/bxi"

ucs_config_field_t uct_bxi_md_config_table[] = {
        {"", "", NULL, ucs_offsetof(uct_bxi_md_config_t, super),
         UCS_CONFIG_TYPE_TABLE(uct_md_config_table)},

        {"GPU_DIRECT_RDMA", "try",
         "Use GPU Direct RDMA for HCA to access GPU pages directly\n",
         ucs_offsetof(uct_bxi_md_config_t, enable_gpudirect_rdma),
         UCS_CONFIG_TYPE_TERNARY},

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
        .max_triggered_ops      = 1024,
        .max_msg_size           = PTL_SIZE_MAX,
        .max_atomic_size        = PTL_SIZE_MAX,
        .max_fetch_atomic_size  = PTL_SIZE_MAX,
        .max_waw_ordered_size   = PTL_SIZE_MAX,
        .max_war_ordered_size   = PTL_SIZE_MAX,
        .max_volatile_size      = PTL_SIZE_MAX,
        .features               = 0,
};

//NOTE: Previous implementation tried to use a counter for OP completion.
//      Unfortunately, there are no guarantees on the order of how the ACK
//      events are received. In other words, even if op1 is executed before
//      op2, it does not mean that first incrementation of the counter
//      correspond to the ACK of op1. As a consequence, and because UCT API
//      is request-based, we MUST use an Event Queue.
//FIXME: Use a memory pool for the MD. Also, the allocate flag makes no sense,
//       remove it sometimes.
ucs_status_t uct_bxi_md_mem_desc_create(uct_bxi_md_t             *md,
                                        uct_bxi_mem_desc_param_t *params,
                                        uct_bxi_mem_desc_t      **mem_desc_p)
{
  ucs_status_t        status;
  uct_bxi_mem_desc_t *mem_desc;
  ptl_md_t            ptl_md;

  //FIXME: recheck if these flags are actually used.
  if (params->flags & UCT_BXI_MEM_DESC_FLAG_ALLOCATE) {
    mem_desc = ucs_malloc(sizeof(uct_bxi_mem_desc_t), "mem_desc");
    if (mem_desc == NULL) {
      status = UCS_ERR_NO_MEMORY;
      goto err;
    }
    mem_desc->flags = UCT_BXI_MEM_DESC_FLAG_ALLOCATE;
  } else {
    /* Memory has already been allocated during memory 
     * pool initialization. */
    mem_desc = *mem_desc_p;
  }

  ptl_md = (ptl_md_t){
          .start     = params->start,
          .length    = params->length,
          .ct_handle = params->cth,
          .eq_handle = params->eqh,
          .options   = params->options,
  };

  status = uct_bxi_wrap(PtlMDBind(md->nih, &ptl_md, &mem_desc->mdh));
  if (status != UCS_OK) {
    goto err_free_memdesc;
  }

  *mem_desc_p = mem_desc;

  return status;

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

  uct_bxi_wrap(PtlMDRelease(mem_desc->mdh));

  if (mem_desc->flags & UCT_BXI_MEM_DESC_FLAG_ALLOCATED) {
    ucs_free(mem_desc);
  }
}

ucs_status_t uct_bxi_mem_reg(uct_md_h uct_md, void *address, size_t length,
                             const uct_md_mem_reg_params_t *params,
                             uct_mem_h                     *memh_p)
{
  ucs_status_t status = UCS_OK;
#ifdef HAVE_GDR_COPY
  uct_bxi_md_t     *md = ucs_derived_of(uct_md, uct_bxi_md_t);
  ucs_memory_info_t mem_info;
  void             *reg_address;
  size_t            reg_length;
  uct_bxi_mem_t    *memh;
  unsigned long     d_ptr;
  int               ret;

  status = ucs_memtype_cache_lookup(address, length, &mem_info);
  //NOTE: mem_info.type is usually resolved through the UCP path. However, for
  //      UCT tests, there are no resolution of the address.
  //FIXME: This condition fails in UCX unit tests but is necessary for NCCL. One
  //       way to overcome this may be to avoid the memcache and implement on our
  //       own memory detection and a rcache.
  if (status == UCS_ERR_NO_ELEM || mem_info.type == UCS_MEMORY_TYPE_UNKNOWN) {
    /* Address was not found in memtype cache or is unknown. This means is must be 
     * a host address. */
    status  = UCS_OK;
    *memh_p = (void *)0xdeadbeef;
    goto out;
  } else if (status == UCS_ERR_UNSUPPORTED) {
    status = UCS_ERR_IO_ERROR;
    goto out;
  }

  //if (mem_info.type != UCS_MEMORY_TYPE_CUDA) {
  //  ucs_error("memtype %s not supported with bxi",
  //            ucs_memory_type_names[mem_info.type]);
  //  status = UCS_ERR_UNSUPPORTED;
  //  goto out;
  //}

  memh = ucs_malloc(sizeof(uct_bxi_mem_t), "bxi gdr_copy handle");
  if (NULL == memh) {
    ucs_error("failed to allocate memory for uct_bxi_mem_t");
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }

  reg_address = address;
  reg_length  = length;

  ucs_align_ptr_range(&reg_address, &reg_length, GPU_PAGE_SIZE);
  d_ptr = ((unsigned long)(char *)reg_address);

  ucs_assert((reg_address != NULL) && (reg_length != 0));

  ret = gdr_pin_buffer(md->gdrcpy_ctx, d_ptr, reg_length, 0, 0, &memh->mh);
  if (ret) {
    ucs_error("bxi gdr_pin_buffer failed. length :%lu ret:%d", reg_length, ret);
    status = UCS_ERR_IO_ERROR;
    goto free_mem;
  }

  ret = gdr_map(md->gdrcpy_ctx, memh->mh, &memh->bar_ptr, reg_length);
  if (ret) {
    ucs_error("bxi gdr_map failed. length :%lu ret:%d", reg_length, ret);
    goto unpin_buffer;
  }

  memh->reg_size = reg_length;

  ret = gdr_get_info(md->gdrcpy_ctx, memh->mh, &memh->info);
  if (ret) {
    ucs_error("bxi gdr_get_info failed. ret:%d", ret);
    status = UCS_ERR_IO_ERROR;
    goto unmap_buffer;
  }

  ucs_trace("bxi registered memory:%p..%p length:%lu info.va:0x%" PRIx64
            " bar_ptr:%p",
            reg_address, UCS_PTR_BYTE_OFFSET(reg_address, reg_length),
            reg_length, memh->info.va, memh->bar_ptr);

  *memh_p = memh;
#endif

out:
  return status;

#ifdef HAVE_GDR_COPY
unmap_buffer:
  ret = gdr_unmap(md->gdrcpy_ctx, memh->mh, memh->bar_ptr, memh->reg_size);
  if (ret) {
    ucs_warn("gdr_unmap failed. unpin_size:%lu ret:%d", memh->reg_size, ret);
  }
unpin_buffer:
  ret = gdr_unpin_buffer(md->gdrcpy_ctx, memh->mh);
  if (ret) {
    ucs_warn("gdr_unpin_buffer failed. ret;%d", ret);
  }
free_mem:
  ucs_free(memh);
#endif
err:
  return status;
}

ucs_status_t uct_bxi_mem_dereg(uct_md_h                         uct_md,
                               const uct_md_mem_dereg_params_t *params)
{
  ucs_status_t status = UCS_OK;
#ifdef HAVE_GDR_COPY
  uct_bxi_md_t  *md = ucs_derived_of(uct_md, uct_bxi_md_t);
  uct_bxi_mem_t *memh;
  int            ret = 0;
#endif

  /* Nothing to do for host memory. */
  if (params->memh == (void *)0xdeadbeef) {
    status = UCS_OK;
    goto out;
  }

#ifdef HAVE_GDR_COPY
  memh = params->memh;
  ret  = gdr_unmap(md->gdrcpy_ctx, memh->mh, memh->bar_ptr, memh->reg_size);
  if (ret) {
    ucs_error("bxi gdr_unmap failed. unpin_size:%lu ret:%d", memh->reg_size,
              ret);
    status = UCS_ERR_IO_ERROR;
    goto out;
  }

  ret = gdr_unpin_buffer(md->gdrcpy_ctx, memh->mh);
  if (ret) {
    ucs_error("bxi gdr_unpin_buffer failed. ret:%d", ret);
    status = UCS_ERR_IO_ERROR;
    goto out;
  }

  ucs_trace("bxi deregistered memory. info.va:0x%" PRIx64 " bar_ptr:%p",
            memh->info.va, memh->bar_ptr);

  ucs_free(memh);
#endif

out:
  return status;
}

ucs_status_t uct_bxi_mkey_pack(uct_md_h uct_md, uct_mem_h uct_memh,
                               void *address, size_t length,
                               const uct_md_mkey_pack_params_t *params,
                               void                            *buffer)
{
  uct_bxi_mem_t *memh = uct_memh;
  void          *p    = buffer;
  unsigned       flags;

  flags = UCS_PARAM_VALUE(UCT_MD_MKEY_PACK_FIELD, params, flags, FLAGS, 0);
  if (flags &
      (UCT_MD_MKEY_PACK_FLAG_INVALIDATE_RMA |
       UCT_MD_MKEY_PACK_FLAG_INVALIDATE_AMO | UCT_MD_MKEY_PACK_FLAG_EXPORT)) {
    return UCS_ERR_UNSUPPORTED;
  }

  if ((void *)memh == (void *)0xdeadbeef) {
    *(void **)buffer = (void *)0xdeadbeef;
  } else {
    /* Necessary data are: BAR pointer gotten after gdrcopy mapping and actual 
     * virtual address. */
    *(void **)p     = memh->bar_ptr;
    p              += sizeof(void *);
    *(uint64_t *)p  = memh->info.va;
  }

  return UCS_OK;
}

ucs_status_t uct_bxi_rkey_unpack(uct_component_t *component,
                                 const void *rkey_buffer, uct_rkey_t *rkey_p,
                                 void **handle_p)
{
  ucs_status_t    status = UCS_OK;
  uct_bxi_rkey_t *rkey;

  if (rkey_buffer == (void *)0xdeadbeef) {
    /* Nothing to unpack since host memory. */
    return UCS_OK;
  }

  rkey = ucs_malloc(sizeof(uct_bxi_rkey_t), "bxi rkey");
  if (rkey == NULL) {
    ucs_error("BXI: could not allocate rkey.");
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }

  rkey->bar_ptr = *(void **)rkey_buffer;
  rkey->vaddr = *(uint64_t *)(UCS_PTR_BYTE_OFFSET(rkey_buffer, sizeof(void *)));

  *rkey_p   = (uct_rkey_t)rkey;
  *handle_p = NULL;

err:
  return status;
}

ucs_status_t uct_bxi_rkey_release(uct_component_t *component,
                                  uct_rkey_t uct_rkey, void *handle)
{
  uct_bxi_rkey_t *rkey = (uct_bxi_rkey_t *)uct_rkey;

  if ((void *)rkey != (void *)0xdeadbeef) {
    ucs_free(rkey);
  }
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
  md_attr->reg_mem_types          = md->reg_mem_types;
  md_attr->gva_mem_types          = 0;
  md_attr->reg_nonblock_mem_types = UCS_BIT(UCS_MEMORY_TYPE_HOST);
  md_attr->cache_mem_types        = UCS_MASK(UCS_MEMORY_TYPE_LAST);
  md_attr->rkey_packed_size       = 0;
  md_attr->reg_cost               = ucs_linear_func_make(9e-9, 0);
  md_attr->rkey_packed_size       = md->rkey_size;

  memcpy(md_attr->global_id, md->super.component->name, component_name_length);

  return UCS_OK;
}

// FIXME: different NET interface needs to be given a unique ptl_interface_t
// value.
static inline ptl_interface_t uct_bxi_parse_device(const char *ptl_device)
{
  ptl_interface_t iface = 0;
  if (strstr(ptl_device, "bxi") == NULL) {
    // Device name from simulator, thus return 0
    iface = 0;
  } else {
    sscanf(ptl_device + 3, "%d", &iface);
  }
  return iface;
}

ucs_status_t uct_bxi_query_md_resources(uct_component_t         *component,
                                        uct_md_resource_desc_t **resources_p,
                                        unsigned *num_resources_p)
{
  ucs_status_t       status     = UCS_OK;
  static const char *bxi_dir[2] = {UCT_BXI_MD_NETDEV_DIR, "/sys/class/net"};
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
      ucs_debug("BXI: could not open bxi directory %s.", bxi_dir[i]);
      continue;
    }

    for (;;) {
      errno = 0;
      entry = readdir(dir);
      if (entry == NULL) {
        if (errno != 0) {
          ucs_error("BXI: could not read bxi directory %s.", bxi_dir[i]);
          status = UCS_ERR_NO_MEMORY;
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

      resources = ucs_realloc(resources, sizeof(*resources) * (num_devices + 1),
                              "bxi resources");
      if (resources == NULL) {
        ucs_error("BXI: could not allocate devices");
        status = UCS_ERR_NO_MEMORY;
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

out:
  return status;
}

void uct_bxi_md_close(uct_md_h uct_md)
{
  uct_bxi_md_t *md = ucs_derived_of(uct_md, uct_bxi_md_t);

#ifdef HAVE_GDR_COPY
  int ret;
  ret = gdr_close(md->gdrcpy_ctx);
  if (ret) {
    ucs_warn("failed to close gdrcopy. ret:%d", ret);
  }
#endif

  uct_bxi_wrap(PtlNIFini(md->nih));

  ucs_free(md->device);

  ucs_free(md);
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_md_config_init(uct_bxi_md_t *md, const uct_bxi_md_config_t *md_config)
{
  // BAR address + virtual address return by gdrcopy_pin
  md->rkey_size = sizeof(void *) + sizeof(uint64_t);
  return;
}

static uct_md_ops_t uct_bxi_md_ops = {
        .close              = uct_bxi_md_close,
        .query              = uct_bxi_md_query,
        .mem_reg            = uct_bxi_mem_reg,
        .mem_dereg          = uct_bxi_mem_dereg,
        .mem_attach         = ucs_empty_function_return_unsupported,
        .mem_advise         = ucs_empty_function_return_unsupported,
        .mkey_pack          = uct_bxi_mkey_pack,
        .detect_memory_type = ucs_empty_function_return_unsupported,
};

static ucs_status_t uct_bxi_set_device_syspath(uct_bxi_md_t *md)
{
  ucs_status_t     status;
  const char      *sysfs_path;
  char            *dev_resolved_path;
  char            *dev_path;
  ucs_sys_device_t sys_dev;

  status = ucs_string_alloc_path_buffer(&dev_path, "dev_path");
  if (status != UCS_OK) {
    goto out;
  }

  status = ucs_string_alloc_path_buffer(&dev_resolved_path, "res_path");
  if (status != UCS_OK) {
    goto out_free_dev_path;
  }

  ucs_snprintf_safe(dev_path, PATH_MAX, "%s/%s", UCT_BXI_MD_NETDEV_DIR,
                    md->device);

  sysfs_path = ucs_topo_resolve_sysfs_path(dev_path, dev_resolved_path);
  sys_dev    = ucs_topo_get_sysfs_dev(md->device, sysfs_path, 10);

  md->sys_dev = sys_dev;

  ucs_free(path_buffer);
out:
  return status;
}

static ucs_status_t uct_bxi_md_open(uct_component_t       *component,
                                    const char            *md_name,
                                    const uct_md_config_t *uct_md_config,
                                    uct_md_h              *md_p)
{
  ucs_status_t               status = UCS_OK;
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
  status = uct_bxi_wrap(PtlNIInit(
          uct_bxi_parse_device(md_name), PTL_NI_MATCHING | PTL_NI_PHYSICAL,
          PTL_PID_ANY, &default_limits, &md->config.limits, &md->nih));
  if (status != UCS_OK) {
    goto err_free_md;
  }

  md->device = ucs_strdup(md_name, "md-name-dup");
  if (md->device == NULL) {
    ucs_error("PTL: Could not allocate bxi device name");
    status = UCS_ERR_NO_MEMORY;
    goto err_nifini;
  }

  /* retrieve the process identifier */
  status = uct_bxi_wrap(PtlGetPhysId(md->nih, &md->pid));
  if (status != UCS_OK) {
    goto err_freedev;
  }

  status = uct_bxi_set_device_syspath(md);
  if (status != UCS_OK) {
    goto err_freedev;
  }

  md->reg_mem_types |= UCS_BIT(UCS_MEMORY_TYPE_HOST);

#ifdef HAVE_GDR_COPY
  /* Initialize gdr context */
  md->gdrcpy_ctx = NULL;
  if (md_config->enable_gpudirect_rdma != UCS_NO) {
    md->gdrcpy_ctx = gdr_open();
    if (md->gdrcpy_ctx == NULL) {
      ucs_error("failed to open gdr copy");
      status = UCS_ERR_IO_ERROR;
      goto err_freedev;
    }

    md->reg_mem_types |= UCS_BIT(UCS_MEMORY_TYPE_CUDA);
  }

  if (!md->gdrcpy_ctx && (md_config->enable_gpudirect_rdma == UCS_YES)) {
    ucs_error("Couldn't enable GPUDirect RDMA. Please make sure "
              "gdrcopy is installed correctly");
    status = UCS_ERR_UNSUPPORTED;
    goto err_freedev;
  }
#endif

  md->reg_cost        = UCS_LINEAR_FUNC_ZERO;
  md->super.ops       = &uct_bxi_md_ops;
  md->super.component = component;

  *md_p = &md->super;

  return status;

err_freedev:
  ucs_free(md->device);
err_nifini:
  PtlNIFini(md->nih);
err_free_md:
  ucs_free(md);
err:
  return status;
}

uct_component_t uct_bxi_component = {
        .query_md_resources = uct_bxi_query_md_resources,
        .md_open            = uct_bxi_md_open,
        .cm_open            = ucs_empty_function_return_unsupported,
        .rkey_unpack        = uct_bxi_rkey_unpack,
        .rkey_ptr           = ucs_empty_function_return_unsupported,
        .rkey_release       = uct_bxi_rkey_release,
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
