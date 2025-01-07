#ifndef UCP_OPERATION_H_
#define UCP_OPERATION_H_

#include "tcache.h"
#include <ucp/core/ucp_worker.h>

typedef struct ucp_offload_context       *ucp_offload_context_h;
typedef struct ucp_offload_context_params ucp_offload_context_params_t;

struct ucp_offload_context {
  ucp_tcache_t       *tcache;
  ucp_worker_iface_t *wiface;
};

ucs_status_t ucp_offload_context_create(ucp_worker_iface_t           *wiface,
                                        ucp_offload_context_params_t *params,
                                        ucp_offload_context_h        *ctx);

void ucp_offload_context_fini(ucp_offload_context_h ctx);

#endif
