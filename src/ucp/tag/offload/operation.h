#ifndef UCP_OPERATION_H_
#define UCP_OPERATION_H_

#include <ucp/api/ucp_def.h>
#include <uct/api/uct_def.h>

ucs_status_t ucp_offload_get_context(ucp_offload_context_h ctx, void *address,
                                     size_t length, uct_oop_ctx_h *oop_ctx_p);

#endif
