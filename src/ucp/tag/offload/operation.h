#ifndef UCP_OPERATION_H_
#define UCP_OPERATION_H_

#include "tcache.h"

typedef struct ucp_offload_context       *ucp_offload_context_h;
typedef struct ucp_offload_context_params ucp_offload_context_params_t;

ucs_status_t ucp_offload_context_create(ucp_offload_context_params_t *params,
                                        ucp_offload_context_h        *ctx);

#endif
