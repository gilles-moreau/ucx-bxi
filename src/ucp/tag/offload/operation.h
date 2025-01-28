#ifndef UCP_OPERATION_H_
#define UCP_OPERATION_H_

#include <ucp/api/ucp_def.h>
#include <uct/api/uct_def.h>

enum {
  UCP_OFFLOAD_CTX_FLAG_CREATE_IF_NOT_FOUND = UCS_BIT(0)
};

ucs_status_t ucp_offload_get_context(ucp_offload_context_h ctx, void *address,
                                     size_t length, unsigned flags,
                                     uct_oop_ctx_h *oop_ctx_p);

#endif
