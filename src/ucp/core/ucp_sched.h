#ifndef UCP_SCHED_H_
#define UCP_SCHED_H_

#include <ucp/api/ucp.h>
#include <ucp/api/ucp_def.h>
#include <uct/api/uct_def.h>

#include <ucs/datastruct/list.h>
#include <ucs/datastruct/queue.h>
#include "ucs/datastruct/queue_types.h"
#include "ucs/sys/compiler_def.h"

#include <config.h>

typedef struct ucp_request ucp_request_t;

#define UCP_SCHED_MAX_SCHEDULE_SIZE 256
#define UCP_SCHED_MAX_DEPS          32

enum {
  UCP_SCHED_OFFLOAD_ENABLED = UCS_BIT(0),
  UCP_SCHED_IMPLICIT = UCS_BIT(1),
};

enum {
  UCP_SCHED_TASK_OFFLOADED     = UCS_BIT(0),
  UCP_SCHED_TASK_RELEASE_SCHED = UCS_BIT(1),
  UCP_SCHED_TASK_COMPLETED     = UCS_BIT(2),
  UCP_SCHED_TASK_SEND          = UCS_BIT(3),
  UCP_SCHED_TASK_RECV          = UCS_BIT(4),
  UCP_SCHED_TASK_MCPY          = UCS_BIT(5),
};

typedef struct ucp_sched_task {
  unsigned               flags;
  void                  *buffer;
  size_t                 size;
  ucp_ep_h               ep;
  uct_tag_t              tag;
  uct_gop_h              comph; /* Transport completion handle */
  ucs_list_link_t        elem;  /* Element in the schedule list */
  ucs_queue_elem_t       qelem; /* Element in the ready queue */
  uct_pending_req_t     *pend_req; /* Pending request to progress send operation */
  struct ucp_sched_task *deps[UCP_SCHED_MAX_DEPS];
  struct ucp_sched_task *succs[UCP_SCHED_MAX_DEPS]; /* tasks depending on this one */
  struct ucp_sched_task *mcpy_twin; /* twin task of a scheduled memcpy operation */
  size_t                 num_deps;
  size_t                 num_succs; /* number of tasks depending on this one */
  size_t                 rem_deps; /* number of not yet completed dependencies (remaining dependencies) */
} ucp_sched_task_t;

typedef unsigned (*ucp_sched_set_deps_func_t)(ucp_sched_h sched, ucp_request_t *req, ucp_sched_task_h task, ucp_deps_param_t *deps_param);
typedef void (*ucp_sched_task_complete_func_t)(ucp_sched_h sched, ucp_sched_task_h task);
typedef void (*ucp_sched_init_recv_task_func_t)(ucp_sched_h sched, ucp_request_t *req);
typedef ucp_sched_task_h (*ucp_sched_init_send_task_func_t)(ucp_sched_h sched, ucp_request_t *req);


typedef struct ucp_sched_ops {
  ucp_sched_init_recv_task_func_t init_recv_task;
  ucp_sched_init_send_task_func_t init_send_task;
  ucp_sched_set_deps_func_t       set_deps;
  ucp_sched_task_complete_func_t  complete_cb;
} ucp_sched_ops_t ;

typedef struct ucp_sched {
  ucp_sched_task_t tasks_mp[UCP_SCHED_MAX_SCHEDULE_SIZE];
  unsigned         flags;
  ucs_list_link_t  schedule;
  size_t           count;
#if ENABLE_MT
  int              fd; /* used for progress thread polling */
#endif
  int              cbq_id; /* id of the callback in the progress callbackq */
  ucp_sched_ops_t  ops;
  ucs_queue_head_t ready; 
  ucp_worker_h     worker;
} ucp_sched_t;

ucs_status_t ucp_sched_send(ucp_sched_h sched, ucp_request_t *req, const ucp_request_param_t *request_param);
ucs_status_t ucp_sched_progress_wrapper(uct_pending_req_t *self);
ucs_status_t ucp_sched_recv(ucp_sched_h sched, ucp_request_t *req);

ucs_status_t ucp_sched_create(ucp_worker_h worker, ucp_sched_mode_t mode, ucp_sched_h *ctx_p);

#endif
