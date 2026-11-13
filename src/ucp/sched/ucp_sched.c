#include "ucp_sched.h"
#include "ucp_sched.inl"

#include <ucp/core/ucp_request.inl>
#include <ucp/core/ucp_worker.h>
#include <ucs/datastruct/khash.h>
#include <ucs/datastruct/mpool.inl>

#define UCP_SCHED_INITIAL_TASKS   32
#define UCP_SCHED_INITIAL_EDGES   128
#define UCP_SCHED_PROGRESS_BUDGET 32

static const char *ucp_sched_type_to_str[UCP_SCHED_TASK_TYPE_LAST] = {
        [UCP_SCHED_TASK_TYPE_SEND] = "send",
        [UCP_SCHED_TASK_TYPE_RECV] = "recv",
        [UCP_SCHED_TASK_TYPE_PUT]  = "put",
        [UCP_SCHED_TASK_TYPE_GET]  = "get",
        [UCP_SCHED_TASK_TYPE_AMO]  = "amo"};

static ucs_mpool_ops_t ucp_sched_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = NULL,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

static ucp_sched_task_ops_t recv_ops;

static ucs_status_t ucp_sched_mpool_init(ucs_mpool_t *mp, size_t elem_size,
                                         unsigned    initial_size,
                                         const char *name)
{
  ucs_mpool_params_t params;

  ucs_mpool_params_reset(&params);
  params.elem_size       = elem_size;
  params.alignment       = sizeof(void *);
  params.elems_per_chunk = initial_size;
  params.grow_factor     = 2.0;
  params.ops             = &ucp_sched_mpool_ops;
  params.name            = name;
  return ucs_mpool_init(&params, mp);
}

static ucp_sched_task_t *ucp_sched_task_alloc(ucp_sched_h sched)
{
  ucp_sched_task_t *task = ucs_mpool_get_inline(&sched->task_mp);

  if (task != NULL) {
    ++sched->count;
  }
  return task;
}

/* Used only before publishing the task in the schedule. */
static void ucp_sched_task_unalloc(ucp_sched_h sched, ucp_sched_task_t *task)
{
  ucs_assert(sched->count != 0);
  --sched->count;
  ucs_mpool_put_inline(task);
}

static ucp_sched_edge_t *ucp_sched_edge_alloc(ucp_sched_h sched)
{
  return ucs_mpool_get_inline(&sched->edge_mp);
}

static void ucp_sched_edge_del(ucp_sched_h sched, ucp_sched_edge_t *edge)
{
  ucs_list_del(&edge->from_link);
  ucs_list_del(&edge->to_link);

  ucs_assert(edge->to->num_deps != 0);
  --edge->to->num_deps;
  if (!(edge->from->flags & UCP_SCHED_TASK_FLAG_COMPLETED)) {
    ucs_assert(edge->to->remaining_deps != 0);
    --edge->to->remaining_deps;
  }

  ucs_mpool_put_inline(edge);
}

static void ucp_sched_remove_incoming(ucp_sched_h sched, ucp_sched_task_t *task)
{
  ucp_sched_edge_t *edge, *tmp;

  ucs_list_for_each_safe (edge, tmp, &task->predecessors, to_link) {
    ucp_sched_edge_del(sched, edge);
  }
}

static ucs_status_t ucp_sched_edge_add(ucp_sched_h       sched,
                                       ucp_sched_task_t *from,
                                       ucp_sched_task_t *to)
{
  ucp_sched_edge_t *edge = ucp_sched_edge_alloc(sched);

  if (edge == NULL) {
    return UCS_ERR_NO_MEMORY;
  }

  edge->from = from;
  edge->to   = to;
  ucs_list_add_tail(&from->successors, &edge->from_link);
  ucs_list_add_tail(&to->predecessors, &edge->to_link);
  ++to->num_deps;

  if (!(from->flags & UCP_SCHED_TASK_FLAG_COMPLETED)) {
    ++to->remaining_deps;
  }

  return UCS_OK;
}

static ucs_status_t ucp_sched_task_send_progress(ucp_sched_task_t *task)
{
  ucp_request_send(task->req);
  return UCS_OK;
}

static ucs_status_ptr_t ucp_sched_task_send_commit(ucp_sched_task_t *task)
{
  return UCS_STATUS_PTR(UCS_OK);
}

static ucp_sched_task_ops_t send_ops = {.commit = ucp_sched_task_send_commit,
                                        .progress =
                                                ucp_sched_task_send_progress};

static ucs_status_t ucp_sched_task_recv_progress(ucp_sched_task_t *task)
{
  return UCS_OK;
}

static ucs_status_ptr_t ucp_sched_task_recv_commit(ucp_sched_task_t *task)
{

  if (task->remaining_deps > 0) {
    ucs_trace("SCHED: task %p commit in progress", task);
    return UCS_STATUS_PTR(UCS_INPROGRESS);
  }

  return UCS_STATUS_PTR(UCS_OK);
}

static ucp_sched_task_ops_t recv_ops = {.commit = ucp_sched_task_recv_commit,
                                        .progress =
                                                ucp_sched_task_recv_progress};

ucs_status_t ucp_sched_task_init(ucp_sched_t *sched, ucp_request_t *req,
                                 ucp_sched_task_type_t type, void *in,
                                 void *out, size_t size, ucp_ep_h ep,
                                 ucp_sched_task_t **task_p)
{
  ucp_sched_task_t *task;

  ucs_assert(sched);

  task = ucp_sched_task_alloc(sched);
  if (task == NULL) {
    return UCS_ERR_NO_MEMORY;
  }

  task->type  = type;
  task->in    = in;
  task->out   = out;
  task->size  = size;
  task->ep    = ep;
  task->sched = sched;
  task->req   = req;

  task->num_deps       = 0;
  task->remaining_deps = 0;
  ucs_list_head_init(&task->predecessors);
  ucs_list_head_init(&task->successors);

  switch (type) {
  case UCP_SCHED_TASK_TYPE_RECV:
    task->ops = recv_ops;
    break;
  case UCP_SCHED_TASK_TYPE_SEND:
  case UCP_SCHED_TASK_TYPE_PUT:
  case UCP_SCHED_TASK_TYPE_GET:
  case UCP_SCHED_TASK_TYPE_AMO:
    task->ops = send_ops;
    break;
  case UCP_SCHED_TASK_TYPE_LAST:
    break;
  }

  *task_p = task;

  return UCS_OK;
}

static UCS_F_ALWAYS_INLINE int ucp_sched_check_overlap(const void *a_buf,
                                                       size_t      a_size,
                                                       const void *b_buf,
                                                       size_t      b_size)
{
  uintptr_t a = (uintptr_t)a_buf;
  uintptr_t b = (uintptr_t)b_buf;

  if ((a_size == 0) || (b_size == 0) || (a_buf == NULL) || (b_buf == NULL)) {
    return 0;
  }

  return (a <= b) ? ((b - a) < a_size) : ((a - b) < b_size);
}

static int ucp_sched_depends_on(const ucp_sched_task_t *task,
                                const ucp_sched_task_t *prev)
{
  if (task->type == UCP_SCHED_TASK_TYPE_RECV) {
    /* Receive task cannot be executed if a previous task's input buffer 
     * overlap. Otherwise, it may overwrite its data before prev task has 
     * been executed. */
    if (ucp_sched_check_overlap(task->out, task->size, prev->in, prev->size)) {
      return 1;
    }
  } else {
    if (ucp_sched_check_overlap(task->in, task->size, prev->out, prev->size)) {
      return 1;
    }

    if ((task->type == UCP_SCHED_TASK_TYPE_SEND) &&
        (prev->type == UCP_SCHED_TASK_TYPE_SEND) && (task->ep == prev->ep)) {
      return 1;
    }
  }

  return 0;
}

ucs_status_ptr_t ucp_sched_task_schedule(ucp_sched_task_t *task)
{
  ucs_status_t      status;
  ucp_sched_t      *sched = task->sched;
  ucp_sched_task_t *prev;

  ucs_assert(task);

  ucs_list_for_each (prev, &sched->schedule, elem) {
    if (!ucp_sched_depends_on(task, prev)) {
      continue;
    }

    ucs_trace("SCHED:\tdepends on. task=%p, type=%s, region %p..%p", prev,
              ucp_sched_type_to_str[prev->type], prev->out,
              UCS_PTR_BYTE_OFFSET(prev->out, prev->size));

    status = ucp_sched_edge_add(sched, prev, task);
    if (status != UCS_OK) {
      ucp_sched_remove_incoming(sched, task);
      ucp_sched_task_unalloc(sched, task);
      return UCS_STATUS_PTR(status);
    }
  }

  ucs_list_add_tail(&sched->schedule, &task->elem);
  ucp_sched_make_ready(sched, task);

  return task->ops.commit(task);
}

static void ucp_sched_destroy(ucp_sched_t *sched)
{
  ucp_sched_task_t *task, *tmp_task;
  ucp_sched_edge_t *edge, *tmp_edge;
  khiter_t          iter;

  if (sched->progress_id != UCS_CALLBACKQ_ID_NULL) {
    /* Caller must serialize the worker progress queue with destruction. */
    ucs_callbackq_remove(&sched->worker->uct->progress_q, sched->progress_id);
    sched->progress_id = UCS_CALLBACKQ_ID_NULL;
  }

  iter = kh_get(ucp_tag_sched_hash, &sched->worker->tm.sched_hash, sched);
  if (iter != kh_end(&sched->worker->tm.sched_hash)) {
    kh_del(ucp_tag_sched_hash, &sched->worker->tm.sched_hash, iter);
  }

  /* Put all graph edges back before returning any tasks, since both edge
     * endpoints point at pooled task objects. This also makes leak checking
     * during ucs_mpool_cleanup() meaningful. */
  ucs_list_for_each (task, &sched->schedule, elem) {
    if (task->flags & UCP_SCHED_TASK_FLAG_RELEASE_SCHED) {
      uct_iface_tag_sched_release(sched->worker->tm.offload.iface->iface,
                                  task->comph);
    }

    ucs_list_for_each_safe (edge, tmp_edge, &task->successors, from_link) {
      ucp_sched_edge_del(sched, edge);
    }
  }

  ucs_list_for_each_safe (task, tmp_task, &sched->schedule, elem) {
    if (task->flags & UCP_SCHED_TASK_FLAG_READY) {
      ucs_list_del(&task->ready_elem);
    }
    ucs_list_del(&task->elem);
    ucs_assert(ucs_list_is_empty(&task->predecessors));
    ucs_assert(ucs_list_is_empty(&task->successors));
    ucs_mpool_put_inline(task);
  }

  ucs_mpool_cleanup(&sched->edge_mp, 1);
  ucs_mpool_cleanup(&sched->task_mp, 1);
  ucs_mpool_put(sched);
}

unsigned ucp_sched_progress_cb(void *arg)
{
  ucs_status_t      status;
  ucp_sched_t      *sched = (ucp_sched_t *)arg;
  ucp_sched_task_t *task;
  unsigned          progressed = 0;

  ucs_assert(!sched->progressing);
  sched->progressing = 1;

  while (!ucs_list_is_empty(&sched->ready) &&
         (progressed < UCP_SCHED_PROGRESS_BUDGET) && !sched->closing) {
    task = ucs_list_extract_head(&sched->ready, ucp_sched_task_t, ready_elem);
    task->flags &= ~UCP_SCHED_TASK_FLAG_READY;
    task->flags |= UCP_SCHED_TASK_FLAG_STARTED;

    status = task->ops.progress(task);
    if (status != UCS_OK) {
      return status;
    }

    ++progressed;
  }

  sched->progressing = 0;
  if (sched->closing) {
    ucp_sched_destroy(sched);
  }

  return progressed;
}

ucs_status_t ucp_sched_create(ucp_worker_h worker, ucp_sched_h *sched_p)
{
  ucp_sched_h  sched;
  ucs_status_t status;
  int          ret;

  sched = ucs_mpool_get(&worker->tm.sched_mp);
  if (sched == NULL) {
    return UCS_ERR_NO_MEMORY;
  }

  sched->flags       = 0;
  sched->count       = 0;
  sched->worker      = worker;
  sched->progress_id = UCS_CALLBACKQ_ID_NULL;
  sched->progressing = 0;
  sched->closing     = 0;
  ucs_list_head_init(&sched->schedule);
  ucs_list_head_init(&sched->ready);

  status = ucp_sched_mpool_init(&sched->task_mp, sizeof(ucp_sched_task_t),
                                UCP_SCHED_INITIAL_TASKS, "ucp_sched_tasks");
  if (status != UCS_OK) {
    goto err_sched;
  }

  status = ucp_sched_mpool_init(&sched->edge_mp, sizeof(ucp_sched_edge_t),
                                UCP_SCHED_INITIAL_EDGES, "ucp_sched_edges");
  if (status != UCS_OK) {
    goto err_task_mp;
  }

  kh_put(ucp_tag_sched_hash, &worker->tm.sched_hash, sched, &ret);
  if (ret == UCS_KH_PUT_FAILED) {
    status = UCS_ERR_NO_MEMORY;
    goto err_edge_mp;
  }

  sched->progress_id = ucs_callbackq_add_safe(&worker->uct->progress_q,
                                              ucp_sched_progress_cb, sched);
  if (sched->progress_id == UCS_CALLBACKQ_ID_NULL) {
    khiter_t iter = kh_get(ucp_tag_sched_hash, &worker->tm.sched_hash, sched);
    kh_del(ucp_tag_sched_hash, &worker->tm.sched_hash, iter);
    status = UCS_ERR_NO_MEMORY;
    goto err_edge_mp;
  }

  *sched_p = sched;
  return UCS_OK;

err_edge_mp:
  ucs_mpool_cleanup(&sched->edge_mp, 1);
err_task_mp:
  ucs_mpool_cleanup(&sched->task_mp, 1);
err_sched:
  ucs_mpool_put(sched);
  return status;
}

void ucp_sched_fini(ucp_sched_h sched)
{
  ucp_sched_task_t *task;

  /* Destruction with live requests would leave req->task dangling. */
  ucs_list_for_each (task, &sched->schedule, elem) {
    if (task->req != NULL) {
      ucs_error("SCHED: cannot destroy schedule with live task %p", task);
      return;
    }
  }

  if (sched->progressing) {
    sched->closing = 1;
  } else {
    ucp_sched_destroy(sched);
  }
}
