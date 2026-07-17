#ifndef UCP_SCHED_INL_
#define UCP_SCHED_INL_

#include "ucp_request.h"
#include "ucp_sched.h"
#include <ucs/async/eventfd.h>

#define ucp_sched_task_complete(_sched, _task)                                         \
  {                                                                            \
    ucs_assert(!((_task)->flags & UCP_SCHED_TASK_COMPLETED));                  \
                                                                               \
    (_task)->flags |= UCP_SCHED_TASK_COMPLETED;                                \
    ucp_sched_signal_fd(_sched);                                               \
    (_sched)->ops.complete_cb(_sched, _task);                                  \
  }

static UCS_F_ALWAYS_INLINE void ucp_sched_signal_fd(ucp_sched_t *sched) {
#if ENABLE_MT
  if (sched->worker->flags & UCP_WORKER_FLAG_THREAD_MULTI) { 
    ucs_async_eventfd_signal(sched->fd);
  }
#endif
}

static UCS_F_ALWAYS_INLINE int ucp_sched_task_is_offload(ucp_request_t *req)
{
  return (req->flags & UCP_REQUEST_FLAG_SCHEDULED) &&
         (req->task->flags & UCP_SCHED_TASK_OFFLOADED);
}

#endif
