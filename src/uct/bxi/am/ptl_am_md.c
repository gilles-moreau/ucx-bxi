#include "ptl_am_md.h"

#include <ucs/sys/module.h>

static uct_md_ops_t uct_ptl_am_md_ops;

static ucs_config_field_t uct_ptl_am_md_config_table[] = {
    {UCT_PTL_CONFIG_PREFIX, "", NULL, ucs_offsetof(uct_ptl_md_config_t, super),
     UCS_CONFIG_TYPE_TABLE(&uct_ptl_md_config_table)},

    {""},
};

ucs_status_t uct_ptl_am_mem_reg(uct_md_h uct_md, void *address, size_t length,
                                const uct_md_mem_reg_params_t *params,
                                uct_mem_h *memh_p) {
  uct_ptl_am_mr_t *mr;
  ucs_status_t rc = UCS_OK;
  uct_ptl_am_md_t *ptl_md = ucs_derived_of(uct_md, uct_ptl_am_md_t);

  mr = (uct_ptl_am_mr_t *)ucs_malloc(sizeof(uct_ptl_am_mr_t), "am-memh");
  if (mr == NULL) {
    ucs_error("PTL: could not allocate am mr.");
    rc = UCS_ERR_NO_MEMORY;
    goto err;
  }
  mr->super.flags = 0;

  if (params->flags &
      (UCT_MD_MEM_ACCESS_LOCAL_READ | UCT_MD_MEM_ACCESS_LOCAL_WRITE)) {
    ucs_assert(!PtlHandleIsEqual(ptl_md->mmd.mdh, PTL_INVALID_HANDLE));
    mr->mmd = &ptl_md->mmd;
    mr->super.flags |= UCT_PTL_MR_FLAGS_INITIATOR;
  }

  if (params->flags &
      (UCT_MD_MEM_ACCESS_REMOTE_PUT | UCT_MD_MEM_ACCESS_REMOTE_GET)) {
    ucs_assert(!PtlHandleIsEqual(ptl_md->me.meh, PTL_INVALID_HANDLE));
    mr->me = &ptl_md->me;
    mr->super.flags |= UCT_PTL_MR_FLAGS_TARGET;
  }

  *memh_p = mr;

err:
  return rc;
}

ucs_status_t uct_ptl_am_mem_dereg(uct_md_h uct_md,
                                  const uct_md_mem_dereg_params_t *params) {
  uct_ptl_am_mr_t *memh;

  UCT_MD_MEM_DEREG_CHECK_PARAMS(params, 0);

  memh = params->memh;

  ucs_free(memh);

  return UCS_OK;
}

void uct_ptl_am_md_close(uct_md_h uct_md) {
  uct_ptl_am_md_t *md = ucs_derived_of(uct_md, uct_ptl_am_md_t);

  uct_ptl_md_mdesc_fini(&md->mmd);
  uct_ptl_md_me_fini(&md->super, &md->me);

  uct_ptl_wrap(PtlPTFree(md->super.nih, md->super.pti));

  uct_ptl_wrap(PtlNIFini(md->super.nih));

  // FIXME: there seems to be a problem due to static definition of this call in
  // Bull Portails.
  //  PtlFini();

  ucs_free(md->super.device);

  ucs_free(md);
}

static ucs_status_t uct_ptl_am_md_open(uct_component_t *component,
                                       const char *md_name,
                                       const uct_md_config_t *uct_md_config,
                                       uct_md_h *md_p) {
  ucs_status_t rc = UCS_OK;
  uct_ptl_am_md_t *ptl_md;
  uct_ptl_me_param_t me_param;
  uct_ptl_mmd_param_t mmd_param;
  const uct_ptl_am_md_config_t *md_config =
      ucs_derived_of(uct_md_config, uct_ptl_am_md_config_t);

  ptl_md = ucs_derived_of(uct_ptl_md_alloc(sizeof(*ptl_md), "ptl-am-md"),
                          uct_ptl_am_md_t);
  if (ptl_md == NULL)
    goto err;

  rc = uct_ptl_md_init(&ptl_md->super, md_name, &md_config->super);
  if (rc != UCS_OK) {
    goto err_clean_md;
  }

  mmd_param = (uct_ptl_mmd_param_t){
      .flags = PTL_MD_EVENT_CT_ACK | PTL_MD_EVENT_CT_REPLY | PTL_MD_VOLATILE,
  };
  rc = uct_ptl_md_mdesc_init(&ptl_md->super, &mmd_param, &ptl_md->mmd);
  if (rc != UCS_OK) {
    goto err_md_fini;
  }

  /* Memory entry for remote access. */
  me_param = (uct_ptl_me_param_t){
      .match = 0,
      .ign = ~0,
      .start = NULL,
      .length = PTL_SIZE_MAX,
      .flags = PTL_ME_OP_PUT | PTL_ME_OP_GET | PTL_ME_EVENT_LINK_DISABLE |
               PTL_ME_EVENT_UNLINK_DISABLE | PTL_ME_EVENT_COMM_DISABLE,
  };
  rc = uct_ptl_md_me_init(&ptl_md->super, &me_param, &ptl_md->me);
  if (rc != UCS_OK) {
    goto err_mmd_fini;
  }

  ptl_md->super.cap_flags |=
      UCT_MD_FLAG_REG | UCT_MD_FLAG_NEED_MEMH | UCT_MD_FLAG_NEED_RKEY;

  ptl_md->super.super.ops = &uct_ptl_am_md_ops;
  ptl_md->super.super.component = component;

  *md_p = &ptl_md->super.super;

  return rc;

err_mmd_fini:
  uct_ptl_md_mdesc_fini(&ptl_md->mmd);
err_md_fini:
  uct_ptl_md_fini(&ptl_md->super);
err_clean_md:
  ucs_free(ptl_md);
err:
  return rc;
}

ucs_status_t uct_ptl_am_rkey_unpack(uct_component_t *component,
                                    const void *rkey_buffer, uct_rkey_t *rkey_p,
                                    void **handle_p) {
  *rkey_p = 0;
  *handle_p = NULL;
  return UCS_OK;
}

static uct_md_ops_t uct_ptl_am_md_ops = {
    .close = uct_ptl_am_md_close,
    .query = uct_ptl_md_query,
    .mem_reg = uct_ptl_am_mem_reg,
    .mem_dereg = uct_ptl_am_mem_dereg,
    .mem_attach = ucs_empty_function_return_unsupported,
    .mem_advise = ucs_empty_function_return_unsupported,
    .mkey_pack = ucs_empty_function_return_success,
    .detect_memory_type = ucs_empty_function_return_unsupported,
};

uct_component_t uct_ptl_am_component = {
    .query_md_resources = uct_ptl_query_md_resources,
    .md_open = uct_ptl_am_md_open,
    .cm_open = ucs_empty_function_return_unsupported,
    .rkey_unpack = uct_ptl_am_rkey_unpack,
    .rkey_ptr = ucs_empty_function_return_unsupported,
    .rkey_release = ucs_empty_function_return_success,
    .rkey_compare = uct_base_rkey_compare,
    .name = "ptl_am",
    .md_config =
        {
            .name = "PTL AM memory domain",
            .prefix = UCT_PTL_AM_CONFIG_PREFIX,
            .table = uct_ptl_am_md_config_table,
            .size = sizeof(uct_ptl_am_md_config_t),
        },
    .cm_config = UCS_CONFIG_EMPTY_GLOBAL_LIST_ENTRY,
    .tl_list = UCT_COMPONENT_TL_LIST_INITIALIZER(&uct_ptl_am_component),
    .flags = 0,
    .md_vfs_init = (uct_component_md_vfs_init_func_t)ucs_empty_function,
};
