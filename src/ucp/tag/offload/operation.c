#include "operation.h"

#include <uct/api/uct.h>

static ucs_status_t ucp_mem_offload_context(void *context, ucp_tcache_t *tcache,
                                            void                *arg,
                                            ucp_tcache_region_t *region,
                                            uint16_t             flags)
{
  ucp_offload_context_h ctx = context;

  return uct_iface_tag_created_oop_ctx(ctx->wiface->iface, &region->oop);
}

static void ucp_mem_unoffload_context(void *context, ucp_tcache_t *tcache,
                                      ucp_tcache_region_t *region)
{
  ucp_offload_context_h ctx = context;

  uct_iface_tag_delete_oop_ctx(ctx->wiface->iface, region->oop);
}

ucs_status_t ucp_offload_context_create(ucp_worker_h           worker,
                                        ucp_offload_context_h *ctx_p)
{
  ucs_status_t          status;
  ucp_tcache_params_t   tcache_params;
  ucp_offload_context_h ctx;

  ucs_assert(worker->num_active_ifaces == 1 &&
             worker->tm.offload.iface != NULL);

  ctx = ucs_malloc(sizeof(struct ucp_offload_context), "alloc oop ctx");
  if (ctx == NULL) {
    ucs_error("OOP: could not allocate offload operation context.");
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }

  tcache_params.ops.mem_off        = ucp_mem_offload_context;
  tcache_params.ops.mem_unoff      = ucp_mem_unoffload_context;
  tcache_params.context            = ctx;
  tcache_params.max_size           = 1024;
  tcache_params.region_struct_size = sizeof(ucp_tcache_region_t);

  status = ucp_tcache_create(&tcache_params, "tcache", NULL, &ctx->tcache);
  if (status != UCS_OK) {
    goto err;
  }

  //TODO: add worker resources availability checks.

  ctx->wiface = worker->tm.offload.iface;

  *ctx_p = ctx;
err:
  return status;
}

void ucp_offload_context_fini(ucp_offload_context_h ctx)
{
  ucp_tcache_destroy(ctx->tcache);

  ucs_free(ctx);
}
