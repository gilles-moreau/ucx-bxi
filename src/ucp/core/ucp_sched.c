#include "ucp_sched.h"
#include "api/ucp.h"
#include "api/ucp_def.h"
#include "ucs/datastruct/callbackq.h"
#include "ucs/datastruct/queue.h"
#include "ucs/datastruct/queue_types.h"
#include "ucs/sys/compiler_def.h"
#include "ucs/type/status.h"

#include <string.h>
#include <ucp/core/ucp_ep.h>
#include <ucp/core/ucp_request.h>
#include <ucp/core/ucp_worker.h>
#include <ucp/proto/proto_common.h>
#include <ucp/rndv/proto_rndv.h>
#include <ucs/datastruct/khash.h>
#include <ucs/datastruct/list.h>
#include <ucs/profile/profile.h>
#include <uct/api/uct.h>
#include <uct/base/uct_iface.h>
#include <ucs/async/eventfd.h>
#include <ucs/async/async_fwd.h>

void ucp_sched_task_ready_succs(ucp_sched_h sched, ucp_sched_task_h task) {
  ucp_sched_task_h succ;
  if (task->flags & UCP_SCHED_TASK_COMPLETED) {
    for (int i=0; i<task->num_succs; i++) {
      succ = task->succs[i];
      succ->rem_deps--;
      if (succ->rem_deps == 0 && !(succ->flags & UCP_SCHED_TASK_OFFLOADED)) {
        ucs_queue_push(&sched->ready, &succ->qelem);
      }
    }
  }
}

unsigned ucp_sched_progress_cb(void *arg) {
  ucs_status_t status;
  unsigned count = 0;
  ucp_sched_h sched = arg;
  ucp_sched_task_h task;
  ucs_queue_iter_t iter;
  ucs_queue_for_each_safe(task, iter, &sched->ready, qelem) {
    /* progress task */
    status = task->pend_req->func(task->pend_req);
    if (status == UCS_OK) {
      /* pending request completed so it should be removed from the queue */
      ucs_queue_del_iter(&sched->ready, iter);
      count++;
    }
  }
  return count;
}

ucp_sched_task_h ucp_sched_task_init(ucp_sched_h sched) {
  ucp_sched_task_t *task  = &sched->tasks_mp[sched->count++];
  task->flags             = 0;
  task->num_deps          = 0;
  task->num_succs         = 0;
  task->rem_deps          = 0;
  return task;
}

void ucp_sched_recv_task_init(ucp_sched_h sched, ucp_request_t *req) {
  /* Assign task from the schedule pool. */
  req->task         = ucp_sched_task_init(sched);
  req->task->flags  = UCP_SCHED_TASK_RECV;
}

void ucp_sched_recv_task_init_implicit(ucp_sched_h sched, ucp_request_t *req) {
  /* Assign task from the schedule pool. */
  ucp_sched_recv_task_init(sched, req);
  req->task->buffer = req->recv.dt_iter.type.contig.buffer;
  req->task->size   = req->recv.dt_iter.length;
  /* Append receive task to schedule. */
  ucs_list_add_head(&sched->schedule, &req->task->elem);
}

// Add a region to the sched
UCS_PROFILE_FUNC(ucs_status_t, ucp_sched_recv, (sched, req), ucp_sched_h sched, ucp_request_t *req)
{
  ucs_status_t        status = UCS_OK;
  ucp_worker_iface_t *wiface;

  ucs_assert(sched != NULL);
  //FIXME: for some reason, assertion was raised. To be checked.
  //ucs_assert(req->recv.dt_iter.dt_class == UCP_DATATYPE_CONTIG);

  if (sched->count >= UCP_SCHED_MAX_SCHEDULE_SIZE) {
    ucs_error("schedule size overflow. count=%lu, max=%d", sched->count,
              UCP_SCHED_MAX_SCHEDULE_SIZE);
    return UCS_ERR_NO_MEMORY;
  }
  /* Assign task from the schedule pool. */
  sched->ops.init_recv_task(sched, req);

  if ((sched->flags & UCP_SCHED_OFFLOAD_ENABLED) &&
      (req->flags & UCP_REQUEST_FLAG_OFFLOADED)) {
    wiface = sched->worker->tm.offload.iface;

    status = uct_iface_tag_sched_recv(wiface->iface, &req->recv.uct_ctx,
                                      &req->task->comph);
    if (status != UCS_OK) {
      return status;
    }

    //FIXME: how do we know when to release a gop?
    req->task->flags |= UCP_SCHED_TASK_OFFLOADED | UCP_SCHED_TASK_RELEASE_SCHED;
  }

  ucp_trace_req(
          req,
          "scheduled recv task %p. offloaded ? %d, size %lu, region %p..%p",
          req->task, !!(req->task->flags & UCP_SCHED_TASK_OFFLOADED),
          req->task->size, req->task->buffer,
          UCS_PTR_BYTE_OFFSET(req->task->buffer, req->task->size));
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

// Remove a region from the sched
ucs_status_t ucp_sched_remove_task(ucp_sched_h sched, ucp_sched_task_h task)
{
  if (task->flags & UCP_SCHED_TASK_COMPLETED) {
    ucs_list_del(&(task->elem));
  }
  return UCS_OK;
}

// Task completion callback
void ucp_sched_task_implicit_complete_cb(ucp_sched_h sched, ucp_sched_task_h task) {
  // Remove region from the sched to optimize regions overlap search
  // FIXME can it create an error on send tasks if elem is not added to a list?  
  ucp_sched_remove_task(sched, task);
  // Check for tasks ready to be progressed
  ucp_sched_task_ready_succs(sched, task);
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

unsigned ucp_sched_set_task_explicit_deps(ucp_sched_h schedh, ucp_request_t *req, ucp_sched_task_h task, ucp_deps_param_t *deps_param)
{
  ucp_sched_task_h *deps;
  size_t num_deps = 0;
  unsigned offloaded = UCP_SCHED_TASK_OFFLOADED;

  if (deps_param->num_deps > 0) {
    num_deps = deps_param->num_deps;
    deps = deps_param->deps;
  }
  for (int i=0; i<num_deps; ++i) {
    ucp_sched_task_h dep = deps[i];
    if (dep != NULL) {
      /* To reduce the number of dependencies to ckeck later on */
      if (!(dep->flags & UCP_SCHED_TASK_COMPLETED)) {
        /* Add dep to the list of dependencies. */
        task->deps[task->num_deps++] = dep;
        task->rem_deps++;

        /* Add task to the list of successors of dep */
        dep->succs[dep->num_succs++] = task;

        /* Task may be offloaded only if all dependent tasks have been
          * offloaded. */
        offloaded &= dep->flags & UCP_SCHED_TASK_OFFLOADED;
      }
    }
  }
  return offloaded;
}

unsigned ucp_sched_set_task_implicit_deps(ucp_sched_h schedh, ucp_request_t *req, ucp_sched_task_h stask, ucp_deps_param_t *deps_param) {
  unsigned offloaded = UCP_SCHED_TASK_OFFLOADED;
  ucp_sched_task_t *task;
  
  /* Loop over tasks in the recv schedule to find dependencies. */
  ucs_list_for_each (task, &schedh->schedule, elem) {
    if (task->flags & UCP_SCHED_TASK_SEND) {
      if ((task->ep == stask->ep) && (task->tag == stask->tag) &&
          !(task->flags & UCP_SCHED_TASK_OFFLOADED)) {
        stask->deps[stask->num_deps++] = task;
        stask->rem_deps++;

        /* Add stask to the list of successors of task */
        task->succs[task->num_succs++] = stask;

        //NOTE: task cannot be offloaded, otherwise we would have to manually
        //      increment the counter to count for the non-offloaded dependency.
        offloaded = 0;
      }
    } else { /* UCP_SCHED_TASK_RECV */
      ucp_trace_req(req, "\tcheck overlap region recv %p..%p", task->buffer,
                    UCS_PTR_BYTE_OFFSET(task->buffer, task->size));
      if (ucp_sched_check_overlap(stask->buffer, stask->size, task->buffer,
                                  task->size) &&
          !(task->flags & UCP_SCHED_TASK_COMPLETED)) {
        /* Task has overlapping memory range with non-completed task, thus
        * add it to the list of dependencies. */

        /* Add task to the list of dependencies. */
        stask->deps[stask->num_deps++] = task;
        stask->rem_deps++;

        /* Add stask to the list of successors of task */
          task->succs[task->num_succs++] = stask;

        /* Task may be offloaded only if all dependent tasks have been 
        * offloaded. */
        offloaded &= task->flags & UCP_SCHED_TASK_OFFLOADED;
      }
    }
  }
  return offloaded;
}

/**
 * @brief callback that progress worker while fd @a id is readable
 *
 * @param [in] id     fd of the scheduler
 * @param [in] events unused, the type of event used for polling on the fd
 * @param [in] arg    worker to progress
 */
void ucp_sched_progress(int id, ucs_event_set_types_t events, void *arg) {
  ucp_sched_h sched = arg;
  // Several events can't be detected at a time
  while(ucs_async_eventfd_poll(id) == UCS_OK) {
    UCP_WORKER_THREAD_CS_ENTER_CONDITIONAL(sched->worker);
    ucp_sched_progress_cb(sched);
    UCP_WORKER_THREAD_CS_EXIT_CONDITIONAL(sched->worker);
  }
}

ucs_status_t ucp_sched_progress_wrapper(uct_pending_req_t *self)
{
  ucp_request_t     *req   = ucs_container_of(self, ucp_request_t, send.uct);
  const ucp_proto_t *proto = req->send.proto_config->proto;
  //TODO: bug when protocol is a rndv protocol since priv is not the same...
  ucp_sched_task_t                      *stask = req->task;
  ucp_lane_index_t lane;
  if (strcmp(proto->name, "tag/rndv")==0){
    const ucp_proto_rndv_ctrl_priv_t    *rpriv = req->send.proto_config->priv;
    lane = rpriv->lane;
  } else {
    const ucp_proto_common_lane_priv_t  *spriv = req->send.proto_config->priv;
    lane = spriv->lane;
  }

  if (stask->flags & UCP_SCHED_TASK_OFFLOADED) {
    goto start_send;
  }

  // for (int i = 0; i < stask->num_deps; i++) {
  //   if (!(stask->deps[i]->flags & UCP_SCHED_TASK_COMPLETED)) {
  //     req->send.lane = lane; /* Save for pending_add */
  //     /* Return no resource so request can be added to pending list. */
  //     return UCS_ERR_NO_RESOURCE;
  //   }
  // }
  if (stask->rem_deps != 0) {
    req->send.lane = lane; /* Save for pending_add */ /* FIXME is it still
    * needed since pending_add will not be caled anymore */
    return UCS_OK;
  }

start_send:
  ucp_trace_req(req, "scheduled send task %p can be progressed", req->task);
  if (req->send.ep->worker->context->config.progress_wrapper_enabled) {
    req->send.uct.func = ucp_request_progress_wrapper;
  } else {
    req->send.uct.func = proto->progress[req->send.proto_stage];
  }
  return req->send.uct.func(self);
}

static UCS_F_ALWAYS_INLINE ucs_status_t
ucp_sched_offload_send(ucp_sched_h sched, ucp_sched_task_t *stask)
{
  int                 length = 0;
  ucp_worker_iface_t *wiface;
  uct_gop_h           gops[UCP_SCHED_MAX_SCHEDULE_SIZE];

  /* All dependent tasks were offloaded, this one must also be offloaded. */
  wiface = sched->worker->tm.offload.iface;

  for (int i = 0; i < stask->num_deps; i++) {
    gops[length++] = stask->deps[i]->comph;
  }

  //FIXME: not good since it makes assumption on how the transport
  //       has allocated the gop.
  if (stask->num_deps > 1) {
    stask->flags |= UCP_SCHED_TASK_RELEASE_SCHED;
  }

  return uct_iface_tag_sched_send(wiface->iface, &stask->comph, gops, length);
}

ucp_sched_task_h ucp_sched_send_task_init(ucp_sched_h sched, ucp_request_t *req) {
  ucp_sched_task_t *stask = ucp_sched_task_init(sched);
  stask->pend_req  = &req->send.uct; 
  stask->flags    = UCP_SCHED_TASK_SEND;
  stask->tag      = req->send.msg_proto.tag;
  stask->ep       = req->send.ep;
  return stask;
}

ucp_sched_task_h ucp_sched_send_task_init_implicit(ucp_sched_h sched, ucp_request_t *req) {
  ucp_sched_task_t *stask = ucp_sched_send_task_init(sched, req);
  stask->buffer    = req->send.state.dt_iter.type.contig.buffer;
  stask->size      = req->send.state.dt_iter.length;
  /* FIXME how to handle send->send dependencies in the implicit mode? 
   * Should the list elem be added to the scheduler's schedule list? */
  // ucs_list_add_head(&sched->schedule, &stask->elem);
  return stask;
}

ucs_status_t ucp_sched_send(ucp_sched_h sched, ucp_request_t *req, ucp_deps_param_t *deps_param)
{
  ucs_status_t      status = UCS_OK;
  ucp_sched_task_t *stask;
  unsigned          offloaded = UCP_SCHED_TASK_OFFLOADED;

  ucs_assert(sched != NULL);
  ucs_assert(req->send.state.dt_iter.dt_class == UCP_DATATYPE_CONTIG);

  if (sched->count >= UCP_SCHED_MAX_SCHEDULE_SIZE) {
    ucs_error("schedule size overflow. count=%lu, max=%d", sched->count,
              UCP_SCHED_MAX_SCHEDULE_SIZE);
    return UCS_ERR_NO_MEMORY;
  }

  /* Init task from the scheduler. */
  stask            = sched->ops.init_send_task(sched, req);  

  offloaded &= sched->ops.set_deps(sched, req, stask, deps_param);

  if (stask->num_deps > 0) {
    if (offloaded & UCP_SCHED_TASK_OFFLOADED) {
      /* Task may be scheduled using tranport own scheduler. */
      status = ucp_sched_offload_send(sched, stask);
      if (status != UCS_OK) {
        goto err;
      }
      stask->flags |= UCP_SCHED_TASK_OFFLOADED;
    }
  }

  /* Append send task to schedule. */
  ucs_list_add_head(&sched->schedule, &stask->elem);

  ucp_trace_req(req,
                "scheduled send task %p, region %p..%p, has %lu "
                "dependencies",
                stask, stask->buffer,
                UCS_PTR_BYTE_OFFSET(stask->buffer, stask->size),
                stask->num_deps);
  req->task   = stask;
  req->flags |= UCP_REQUEST_FLAG_SCHEDULED;

err:
  return status;
}

ucs_status_t ucp_sched_create(ucp_worker_h worker, ucp_sched_mode_t mode, ucp_sched_h *sched_p)
{
  ucs_status_t status = UCS_OK;
  ucp_sched_h  sched;
  int          ret;

  sched = ucs_mpool_get(&worker->tm.sched_mp);
  if (sched == NULL) {
    status = UCS_ERR_NO_MEMORY;
    goto err;
  }

#if ENABLE_MT
  if (worker->flags & UCP_WORKER_FLAG_THREAD_MULTI) {
    /* Set progress thread callback */
    status = ucs_async_eventfd_create(&sched->fd);
    if (status != UCS_OK) {
      goto err_fd;
    }
    status = ucs_async_set_event_handler(worker->async.mode, sched->fd, 
                                         UCS_EVENT_SET_EVREAD , 
                                         ucp_sched_progress, worker, &worker->async);
    if (status != UCS_OK) {
      goto err_evfd_handler;
    }
  }
#endif

  sched->flags  = 0;
  sched->count  = 0;
  sched->worker = worker;

  //FIXME set the right functions once they are created
  if (mode & UCP_SCHED_MODE_IMPLICIT) {
    sched->flags |= UCP_SCHED_IMPLICIT;
    sched->ops.init_recv_task = ucp_sched_recv_task_init_implicit;
    sched->ops.init_send_task = ucp_sched_send_task_init_implicit;
    sched->ops.set_deps = ucp_sched_set_task_implicit_deps;
    sched->ops.complete_cb = ucp_sched_task_implicit_complete_cb;
  } else {
    sched->ops.init_recv_task = ucp_sched_recv_task_init;
    sched->ops.init_send_task = ucp_sched_send_task_init;
    sched->ops.set_deps = ucp_sched_set_task_explicit_deps;
    sched->ops.complete_cb = ucp_sched_task_ready_succs;
  }

  ucs_list_head_init(&sched->schedule);

  ucs_queue_head_init(&sched->ready);

  sched->cbq_id = ucs_callbackq_add_safe(&sched->worker->uct->progress_q, ucp_sched_progress_cb, sched);

  /* If offload interface has been activated, enable scheduling on it. */
  if (worker->tm.offload.iface != NULL) {
    //FIXME: multiple interface are not supported
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
#if ENABLE_MT
err_evfd_handler:
    ucs_async_eventfd_destroy(sched->fd);
err_fd:
    ucs_mpool_put(sched);
    return status;
#endif
}

void ucp_sched_fini(ucp_sched_h sched)
{
  ucs_callbackq_remove_safe(&sched->worker->uct->progress_q, sched->cbq_id);

  for (int i = 0; i < sched->count; i++) {
    if (sched->tasks_mp[i].flags & UCP_SCHED_TASK_RELEASE_SCHED) {
      uct_iface_tag_sched_release(sched->worker->tm.offload.iface->iface,
                                  sched->tasks_mp[i].comph);
    }
  }

#if ENABLE_MT
  if (sched->worker->flags & UCP_WORKER_FLAG_THREAD_MULTI) {
    ucs_async_remove_handler(sched->fd, 1);
    ucs_async_eventfd_destroy(sched->fd);
  }
#endif

  ucs_trace_req("schedule released %p", sched);

  ucs_mpool_put(sched);
}
