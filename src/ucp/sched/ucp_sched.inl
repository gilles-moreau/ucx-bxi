#ifndef UCP_SCHED_INL_
#define UCP_SCHED_INL_

#include "ucp_sched.h"

static UCS_F_ALWAYS_INLINE void ucp_sched_make_ready(ucp_sched_t      *sched,
                                                     ucp_sched_task_t *task)
{
  if ((task->flags &
       (UCP_SCHED_TASK_FLAG_READY | UCP_SCHED_TASK_FLAG_STARTED |
        UCP_SCHED_TASK_FLAG_COMPLETED | UCP_SCHED_TASK_FLAG_FAILED)) ||
      (task->remaining_deps != 0)) {
    return;
  }

  task->flags |= UCP_SCHED_TASK_FLAG_READY;
  ucs_list_add_tail(&sched->ready, &task->ready_elem);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_sched_task_complete(ucp_sched_task_t *task, ucs_status_t status)
{
  ucp_sched_h       sched = task->sched;
  ucp_sched_edge_t *edge;

  /* A request may be canceled before its progress callback ran. */
  if (task->flags & UCP_SCHED_TASK_FLAG_READY) {
    ucs_list_del(&task->ready_elem);
    task->flags &= ~UCP_SCHED_TASK_FLAG_READY;
  }

  /* A failed request must not release dependents as though its buffer were
   * correctly produced. Error propagation/cancellation is a separate policy. */
  if (status != UCS_OK) {
    task->flags |= UCP_SCHED_TASK_FLAG_FAILED;
    ucs_error("SCHED: task %p failed (%s); dependents remain blocked", task,
              ucs_status_string(status));
  } else {
    task->flags |= UCP_SCHED_TASK_FLAG_COMPLETED;
    ucs_trace("SCHED: schedule %p task %p type %d is completed.", 
              task->sched, task, task->type);
    ucs_list_for_each (edge, &task->successors, from_link) {
      ucs_assert(edge->to->remaining_deps > 0);
      --edge->to->remaining_deps;
      if (edge->to->remaining_deps == 0) {
        ucp_sched_make_ready(sched, edge->to);
      }
    }
  }

  task->req = NULL;
  return UCS_OK;
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_sched_task_progress(ucp_sched_task_t *task)
{
  return (ucs_status_t)ucp_sched_progress_cb(task->sched);
}

static UCS_F_ALWAYS_INLINE void ucp_sched_task_recv_save_params(
        ucp_sched_task_t *task, const ucp_request_param_t *param, ucp_tag_t tag,
        ucp_tag_t tag_mask, size_t count, void *buffer,
        ucs_status_t (*progress_cb)(ucp_sched_task_t *task))
{
  task->recv.tag      = tag;
  task->recv.tag_mask = tag_mask;
  task->recv.buffer   = buffer;
  task->recv.count    = count;
  task->ops.progress  = progress_cb;
  memcpy(&task->recv.param, param, sizeof(ucp_request_param_t));
}

#endif
