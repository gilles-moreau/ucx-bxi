#ifndef UCP_SCHED_H_
#define UCP_SCHED_H_

#include <ucp/api/ucp_def.h>
#include <uct/api/uct_def.h>

#include <ucs/datastruct/list.h>

#define UCP_OFFLOAD_SCHED_MAX_OVERLAPS 6

typedef struct ucp_offload_region ucp_offload_region_t;

ucs_status_t ucp_offload_sched_region_add(ucp_offload_sched_h sched,
                                          void *buffer, size_t size,
                                          uct_gop_h *op_p);

size_t ucp_offload_sched_region_get_overlaps(ucp_offload_sched_h sched,
                                             void *buffer, size_t size,
                                             uct_gop_h *op_p);

ucs_status_t ucp_offload_sched_create(ucp_worker_h         worker,
                                      ucp_offload_sched_h *ctx_p);

#endif
