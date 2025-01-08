#ifndef UCP_OPERATION_H_
#define UCP_OPERATION_H_

#include "tcache.h"
#include <ucp/core/ucp_worker.h>

struct ucp_offload_context {
  ucp_tcache_t       *tcache;
  ucp_worker_iface_t *wiface;
};

#endif
