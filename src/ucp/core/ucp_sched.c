#include "ucp_sched.h"

#include <ucp/core/ucp_ep.h>
#include <ucp/core/ucp_request.h>
#include <ucp/core/ucp_worker.h>
#include <ucs/datastruct/khash.h>
#include <ucs/datastruct/list.h>
#include <ucs/profile/profile.h>
#include <uct/api/uct.h>
#include <uct/base/uct_iface.h>

// Add a region to the sched
ucs_status_t ucp_sched_recv(ucp_request_t *req)
{
  ucs_status_t        status = UCS_OK;
  ucp_sched_h         sched  = req->schedh;
  ucp_worker_iface_t *wiface;

  ucs_assert(sched != NULL);
  ucs_assert(req->recv.dt_iter.dt_class == UCP_DATATYPE_CONTIG);

  /* Assign task from the schedule pool. */
  req->task         = &sched->tasks_mp[sched->count++];
  req->task->buffer = req->recv.dt_iter.type.contig.buffer;
  req->task->size   = req->recv.dt_iter.length;
  req->task->flags  = 0;

  /* Append receive task to schedule. */
  ucs_list_add_head(&sched->schedule, &req->task->elem);

  if ((sched->flags & UCP_SCHED_OFFLOAD_ENABLED) &&
      (req->flags & UCP_REQUEST_FLAG_OFFLOADED)) {
    wiface = sched->worker->tm.offload.iface;

    status = uct_iface_tag_sched_recv(wiface->iface, &req->recv.uct_ctx,
                                      &req->task->comph);
    if (status != UCS_OK) {
      return status;
    }

    req->task->flags = UCP_SCHED_TASK_OFFLOADED;
  }

  ucp_trace_req(req, "scheduled recv task %p. offloaded ? %d", req->task,
                !!(req->task->flags & UCP_SCHED_TASK_OFFLOADED));
  req->flags |= UCP_REQUEST_FLAG_SCHEDULED;

  return status;
}

// Remove a region from the sched
ucs_status_t ucp_sched_task_remove(ucp_sched_h sched, ucp_request_t *req)
{
  if (req->flags & UCP_REQUEST_FLAG_SCHEDULED) {
    ucs_list_del(&(req->task->elem));
  }
  return UCS_OK;
}

// Check if two memory regions overlap
int ucp_sched_check_overlap(void *a_buf, size_t a_size, void *b_buf,
                            size_t b_size)
{
  uintptr_t a_start = (uintptr_t)a_buf;
  uintptr_t a_end   = a_start + a_size;
  uintptr_t b_start = (uintptr_t)b_buf;
  uintptr_t b_end   = b_start + b_size;
  return a_start < b_end && b_start < a_end;
}

ucs_status_t ucp_sched_progress_wrapper(uct_pending_req_t *self)
{
  ucp_request_t     *req   = ucs_container_of(self, ucp_request_t, send.uct);
  const ucp_proto_t *proto = req->send.proto_config->proto;
  ucp_sched_task_t  *stask = req->task, *task;

  if (stask->flags & UCP_SCHED_TASK_OFFLOADED) {
    goto start_send;
  }

  ucs_list_for_each (task, &stask->deps, delem) {
    if (!(task->flags & UCP_SCHED_TASK_COMPLETED)) {
      /* Return no resource so request can be added to pending list. */
      return UCS_ERR_NO_RESOURCE;
    }
  }

start_send:
  ucp_trace_req(req, "scheduled send task %p can be progressed", req->task);
  req->send.uct.func = proto->progress[req->send.proto_stage];
  return req->send.uct.func(self);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_sched_offload_send(ucp_sched_h sched, ucp_sched_task_t *stask)
{
  int                 length = 0;
  ucp_worker_iface_t *wiface;
  ucp_sched_task_t   *task;
  uct_gop_h           gops[UCP_SCHED_MAX_SCHEDULE_SIZE];

  /* All dependent tasks were offloaded, this one must also be offloaded. */
  wiface = sched->worker->tm.offload.iface;

  ucs_list_for_each (task, &stask->deps, delem) {
    gops[length++] = task->comph;
  }

  return uct_iface_tag_sched_send(wiface->iface, &stask->comph, gops, length);
}

ucs_status_t ucp_sched_send(ucp_request_t *req)
{
  ucs_status_t      status = UCS_OK;
  ucp_sched_h       sched  = req->schedh;
  ucp_sched_task_t *task, *stask;
  unsigned          offloaded = UCP_SCHED_TASK_OFFLOADED;

  ucs_assert(sched != NULL);
  ucs_assert(req->send.state.dt_iter.dt_class == UCP_DATATYPE_CONTIG);

  /* Init task from the scheduler. */
  stask         = &sched->tasks_mp[sched->count++];
  stask->buffer = req->send.state.dt_iter.type.contig.buffer;
  stask->size   = req->send.state.dt_iter.length;
  stask->flags  = 0;
  ucs_list_head_init(&stask->deps);

  /* Loop over tasks in the schedule to find dependencies. */
  ucs_list_for_each (task, &sched->schedule, elem) {
    if (ucp_sched_check_overlap(stask->buffer, stask->size, task->buffer,
                                task->size) &&
        !(task->flags & UCP_SCHED_TASK_COMPLETED)) {
      /* Task has overlapping memory range with non-completed task, thus
       * add it to the list of dependencies. */

      /* Add task to the list of dependencies. */
      ucs_list_add_head(&stask->deps, &task->delem);

      /* Task may be offloaded only if all dependent tasks have been 
       * offloaded. */
      offloaded &= task->flags & UCP_SCHED_TASK_OFFLOADED;
    }
  }

  if (!ucs_list_is_empty(&stask->deps)) {
    if (offloaded & UCP_SCHED_TASK_OFFLOADED) {
      /* Task may be scheduled using tranport own scheduler. */
      status = ucp_sched_offload_send(sched, stask);
      if (status != UCS_OK) {
        goto err;
      }
      stask->flags |= UCP_SCHED_TASK_OFFLOADED;
    }
    req->flags |= UCP_REQUEST_FLAG_SCHEDULED;
  }

  ucp_trace_req(req, "scheduled send task %p, has dependencies %d", stask,
                !!(req->flags & UCP_REQUEST_FLAG_SCHEDULED));
  req->task = stask;

err:
  return status;
}

ucs_status_t ucp_sched_create(ucp_worker_h worker, ucp_sched_h *sched_p)
{
  ucs_status_t status = UCS_OK;
  ucp_sched_h  sched;
  int          ret;

  sched = ucs_mpool_get(&worker->tm.sched_mp);
  if (sched == NULL) {
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }

  //FIXME: add iface attr checks.

  sched->flags  = 0;
  sched->count  = 0;
  sched->worker = worker;
  ucs_list_head_init(&sched->schedule);

  /* If offload interface has been activated, enable scheduling on it. */
  if (worker->tm.offload.iface != NULL) {
    uct_iface_tag_sched_enable(worker->tm.offload.iface->iface);
    sched->flags |= UCP_SCHED_OFFLOAD_ENABLED;
  }

  /* Append the scheduler to the worker's hash table. */
  kh_put(ucp_tag_sched_hash, &worker->tm.sched_hash, sched, &ret);
  ucs_assertv(ret != UCS_KH_PUT_FAILED, "ret %d", ret);

  ucs_trace_req("schedule created %p, offload ? %d", sched,
                !!(UCP_SCHED_OFFLOAD_ENABLED));

  *sched_p = sched;
err:
  return status;
}

void ucp_sched_fini(ucp_sched_h sched)
{
  ucp_sched_task_t *task;

  ucs_list_for_each (task, &sched->schedule, elem) {
    if (task->flags & UCP_SCHED_TASK_OFFLOADED) {
      uct_iface_tag_sched_release(sched->worker->tm.offload.iface->iface,
                                  task->comph);
    }
    task->flags = 0;
  }

  if (sched->worker->tm.offload.iface != NULL) {
    uct_iface_tag_sched_disable(sched->worker->tm.offload.iface->iface);
  }

  ucs_trace_req("schedule released %p", sched);

  ucs_mpool_put(sched);
}
