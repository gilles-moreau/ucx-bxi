#ifndef UCP_SCHED_H_
#define UCP_SCHED_H_

#include <ucp/api/ucp_def.h>
#include <uct/api/uct_def.h>

#include <ucs/datastruct/list.h>

typedef struct ucp_request ucp_request_t;

#define UCP_SCHED_MAX_SCHEDULE_SIZE 256
#define UCP_SCHED_MAX_DEPS          32

enum {
  UCP_SCHED_OFFLOAD_ENABLED = UCS_BIT(0),
};

enum {
  UCP_SCHED_TASK_OFFLOADED     = UCS_BIT(0),
  UCP_SCHED_TASK_RELEASE_SCHED = UCS_BIT(1),
  UCP_SCHED_TASK_COMPLETED     = UCS_BIT(2),
};

typedef struct ucp_sched_task {
  unsigned               flags;
  void                  *buffer;
  size_t                 size;
  uct_gop_h              comph; /* Transport completion handle */
  ucs_list_link_t        elem;  /* Element in the schedule list */
  struct ucp_sched_task *deps[UCP_SCHED_MAX_DEPS];
  size_t                 num_deps;
} ucp_sched_task_t;

typedef struct ucp_sched {
  ucp_sched_task_t tasks_mp[UCP_SCHED_MAX_SCHEDULE_SIZE];
  unsigned         flags;
  ucs_list_link_t  schedule;
  size_t           count;
  ucp_worker_h     worker;
} ucp_sched_t;

ucs_status_t ucp_sched_send(ucp_request_t *req);
ucs_status_t ucp_sched_progress_wrapper(uct_pending_req_t *self);
ucs_status_t ucp_sched_recv(ucp_request_t *req);

ucs_status_t ucp_sched_create(ucp_worker_h worker, ucp_sched_h *ctx_p);

#endif
