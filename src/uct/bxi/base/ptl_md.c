#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "ptl_md.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>

ucs_config_field_t uct_ptl_md_config_table[] = {
    {"", "", NULL, ucs_offsetof(uct_ptl_md_config_t, super),
     UCS_CONFIG_TYPE_TABLE(uct_md_config_table)},

    {NULL}};

static const ptl_ni_limits_t default_limits = {
    .max_entries = INT_MAX,
    .max_unexpected_headers = INT_MAX,
    .max_mds = INT_MAX,
    .max_cts = INT_MAX,
    .max_eqs = INT_MAX,
    .max_pt_index = INT_MAX,
    .max_iovecs = INT_MAX,
    .max_list_size = INT_MAX,
    .max_triggered_ops = INT_MAX,
    .max_msg_size = PTL_SIZE_MAX,
    .max_atomic_size = PTL_SIZE_MAX,
    .max_fetch_atomic_size = PTL_SIZE_MAX,
    .max_waw_ordered_size = PTL_SIZE_MAX,
    .max_war_ordered_size = PTL_SIZE_MAX,
    .max_volatile_size = PTL_SIZE_MAX,
    .features = 0,
};

ucs_status_t uct_ptl_md_query(uct_md_h uct_md, uct_md_attr_v2_t *md_attr) {
  uct_ptl_md_t *md = ucs_derived_of(uct_md, uct_ptl_md_t);
  size_t component_name_length = strlen(md->super.component->name);

  uct_md_base_md_query(md_attr);
  md_attr->max_alloc = ULONG_MAX;
  md_attr->max_reg = ULONG_MAX;
  md_attr->flags = md->cap_flags;
  md_attr->access_mem_types = UCS_BIT(UCS_MEMORY_TYPE_HOST);
  md_attr->reg_mem_types = UCS_BIT(UCS_MEMORY_TYPE_HOST);
  md_attr->gva_mem_types = 0;
  md_attr->reg_nonblock_mem_types = UCS_BIT(UCS_MEMORY_TYPE_HOST);
  md_attr->cache_mem_types = UCS_BIT(UCS_MEMORY_TYPE_HOST);
  md_attr->access_mem_types = UCS_BIT(UCS_MEMORY_TYPE_HOST);
  md_attr->rkey_packed_size = md->rkey_size;
  md_attr->reg_cost = ucs_linear_func_make(9e-9, 0);

  memcpy(md_attr->global_id, md->super.component->name, component_name_length);

  return UCS_OK;
}

ucs_status_t uct_ptl_md_mdesc_init(uct_ptl_md_t *md,
                                   uct_ptl_mmd_param_t *params,
                                   uct_ptl_mmd_t *mmd) {
  ucs_status_t rc;
  ptl_md_t tmp;

  rc = uct_ptl_wrap(PtlCTAlloc(md->nih, &mmd->cth));
  mmd->seqn = 0;

  tmp = (ptl_md_t){
      .start = 0,
      .length = PTL_SIZE_MAX,
      .ct_handle = mmd->cth,
      .eq_handle = PTL_EQ_NONE,
      .options = params->flags,
  };

  rc = uct_ptl_wrap(PtlMDBind(md->nih, &tmp, &mmd->mdh));
  if (rc != UCS_OK) {
    goto err;
  }

  ucs_queue_head_init(&mmd->opq);

err:
  return rc;
}

ucs_status_t uct_ptl_md_mdesc_fini(uct_ptl_mmd_t *mmd) {
  ucs_status_t rc;

  rc = uct_ptl_wrap(PtlCTFree(mmd->cth));
  if (rc != UCS_OK)
    goto err;

  rc = uct_ptl_wrap(PtlMDRelease(mmd->mdh));

err:
  return rc;
}

ucs_status_t uct_ptl_md_me_init(uct_ptl_md_t *md, uct_ptl_me_param_t *param,
                                uct_ptl_me_t *me) {
  ptl_match_bits_t ign = ~0;

  ptl_me_t tmp = {
      .ct_handle = PTL_CT_NONE,
      .match_bits = param->match,
      .ignore_bits = ign,
      .match_id =
          {
              .phys.nid = PTL_NID_ANY,
              .phys.pid = PTL_PID_ANY,
          },
      .min_free = 0,
      .options = param->flags,
      .uid = PTL_UID_ANY,
      .start = param->start,
      .length = param->length,
  };

  return uct_ptl_wrap(
      PtlMEAppend(md->nih, md->pti, &tmp, PTL_PRIORITY_LIST, NULL, &me->meh));
}

ucs_status_t uct_ptl_md_me_fini(uct_ptl_md_t *md, uct_ptl_me_t *me) {
  return uct_ptl_wrap(PtlMEUnlink(me->meh));
}

ucs_status_t uct_ptl_md_mkey_pack(uct_md_h md, uct_mem_h memh, void *address,
                                  size_t length,
                                  const uct_md_mkey_pack_params_t *params,
                                  void *buffer) {
  return UCS_OK;
}

static inline ptl_interface_t uct_ptl_parse_device(const char *ptl_device) {
  ptl_interface_t iface;
  if (strstr(ptl_device, "bxi") == NULL) {
    // Device name from simulator, thus return 0
    iface = 0;
  } else {
    sscanf(UCS_PTR_TYPE_OFFSET(ptl_device, 3), "%d", &iface);
  }
  return iface;
}

ucs_status_t uct_ptl_query_md_resources(uct_component_t *component,
                                        uct_md_resource_desc_t **resources_p,
                                        unsigned *num_resources_p) {
  int rc = UCS_OK;
  static const char *bxi_dir[2] = {"/sys/class/bxi", "/sys/class/net"};
  uct_md_resource_desc_t *resources;
  int i = 0;
  int is_up;
  int num_devices;
  struct dirent *entry;
  DIR *dir;

  resources = NULL;
  num_devices = 0;

  /* Check if bxi are available in with sysfs */
  do {
    dir = opendir(bxi_dir[i]);
    if (dir == NULL) {
      ucs_warn("PTL: could not open bxi directory %s.", bxi_dir[i]);
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
    }

  close_dir:
    closedir(dir);
  } while (num_devices == 0 && ++i < 2);

  *resources_p = resources;
  *num_resources_p = num_devices;

  return rc;
}

ucs_status_t uct_ptl_md_init(uct_ptl_md_t *md, const char *ptl_device,
                             const uct_ptl_md_config_t *config) {

  ucs_status_t rc;
  /* init the driver */
  rc = uct_ptl_wrap(PtlInit());
  if (rc != UCS_OK) {
    goto err;
  }

  /* init one physical interface */
  rc = uct_ptl_wrap(PtlNIInit(uct_ptl_parse_device(ptl_device),
                              PTL_NI_MATCHING | PTL_NI_PHYSICAL, PTL_PID_ANY,
                              &default_limits, &md->limits, &md->nih));
  if (rc != UCS_OK) {
    goto err_ptl_fini;
  }

  md->device = ucs_strdup(ptl_device, "md-name-dup");
  if (md->device == NULL) {
    ucs_error("PTL: Could not allocate ptl device name");
    rc = UCS_ERR_NO_MEMORY;
    goto err_ptl_nifini;
  }

  /* retrieve the process identifier */
  rc = uct_ptl_wrap(PtlGetPhysId(md->nih, &md->pid));
  if (rc != UCS_OK) {
    goto err_ptl_freedev;
  }

  /* Allocate Portals Table Entry for RMA operations. */
  rc = uct_ptl_wrap(PtlPTAlloc(md->nih, 0, PTL_EQ_NONE, PTL_PT_ANY, &md->pti));
  if (rc != UCS_OK) {
    goto err;
  }

  return rc;

err_ptl_freedev:
  ucs_free(md->device);
err_ptl_nifini:
  PtlNIFini(md->nih);
err_ptl_fini:
  PtlFini();
err:
  return rc;
}

uct_ptl_md_t *uct_ptl_md_alloc(size_t size, const char *name) {
  uct_ptl_md_t *md;

  md = ucs_calloc(1, size, name);
  if (md == NULL) {
    ucs_error("failed to allocate memory for md");
  }

  return md;
}

void uct_ptl_md_fini(uct_ptl_md_t *md) {
  uct_ptl_wrap(PtlPTFree(md->nih, md->pti));

  uct_ptl_wrap(PtlNIFini(md->nih));

  PtlFini();

  ucs_free(md->device);

  return;
}
