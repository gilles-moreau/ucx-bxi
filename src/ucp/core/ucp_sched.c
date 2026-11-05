#include "ucp_sched.h"

#include <ucp/core/ucp_ep.h>
#include <ucp/core/ucp_request.h>
#include <ucp/core/ucp_request.inl>
#include <ucp/core/ucp_worker.h>
#include <ucp/proto/proto_common.h>
#include <ucs/datastruct/khash.h>
#include <ucs/datastruct/list.h>
#include <ucs/datastruct/mpool.h>
#include <ucs/profile/profile.h>
#include <uct/api/uct.h>
#include <uct/base/uct_iface.h>

#define UCP_SCHED_INITIAL_TASKS   32
#define UCP_SCHED_INITIAL_EDGES   128
#define UCP_SCHED_PROGRESS_BUDGET 32

static const char *ucp_sched_type_to_str[UCP_SCHED_TASK_LAST] = {
        [UCP_SCHED_TASK_SEND] = "send",
        [UCP_SCHED_TASK_RECV] = "recv",
        [UCP_SCHED_TASK_PUT]  = "put",
        [UCP_SCHED_TASK_GET]  = "get",
        [UCP_SCHED_TASK_AMO]  = "amo"};

static ucs_mpool_ops_t ucp_sched_mpool_ops = {
        .chunk_alloc   = ucs_mpool_chunk_malloc,
        .chunk_release = ucs_mpool_chunk_free,
        .obj_init      = NULL,
        .obj_cleanup   = NULL,
        .obj_str       = NULL};

/* The pool owns chunks and its freelist. Tasks and edges remain at fixed
 * addresses as long as they are checked out from the pool. */
static ucs_status_t ucp_sched_mpool_init(ucs_mpool_t *mp, size_t elem_size,
                                         unsigned    initial_size,
                                         const char *name)
{
  ucs_mpool_params_t params;

  ucs_mpool_params_reset(&params);
  params.elem_size       = elem_size;
  params.alignment       = sizeof(void *); /* No cache-line padding per edge */
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
  if (!(edge->from->flags & UCP_SCHED_TASK_COMPLETED)) {
    ucs_assert(edge->to->remaining_deps != 0);
    --edge->to->remaining_deps;
  }

  ucs_mpool_put_inline(edge);
}

/* The incoming-edge list also makes construction rollback inexpensive. */
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

  if (!(from->flags & UCP_SCHED_TASK_COMPLETED)) {
    ++to->remaining_deps;
  }

  return UCS_OK;
}

ucs_status_t ucp_sched_task_init(ucp_sched_h schedh, ucp_request_t *req,
                                 ucp_sched_task_type_t type, void *in,
                                 void *out, size_t count, ucp_datatype_t dt,
                                 ucp_sched_task_t **task_p)
{
  ucp_sched_task_t *task;

  ucs_assert(UCP_DT_IS_CONTIG(dt));

  task = ucp_sched_task_alloc(schedh);
  if (task == NULL) {
    return UCS_ERR_NO_MEMORY;
  }

  task->schedh         = schedh;
  task->flags          = 0;
  task->type           = type;
  task->req            = req;
  task->in             = in;
  task->out            = out;
  task->size           = ucp_contig_dt_length(dt, count);
  task->comph          = NULL;
  task->num_deps       = 0;
  task->remaining_deps = 0;
  ucs_list_head_init(&task->predecessors);
  ucs_list_head_init(&task->successors);

  switch (task->type) {
  case UCP_SCHED_TASK_SEND:
    task->tag = req->send.msg_proto.tag;
  case UCP_SCHED_TASK_PUT:
  case UCP_SCHED_TASK_GET:
  case UCP_SCHED_TASK_AMO:
    task->ep = req->send.ep;
    break;
  case UCP_SCHED_TASK_RECV:
    break;
  default:
    ucs_error("SCHED: unknown task type");
    goto err;
  }

  *task_p = task;

  return UCS_OK;
err:
  ucp_sched_task_unalloc(schedh, task);
  return UCS_ERR_INVALID_PARAM;
}

/* The caller is responsible for serializing scheduler modifications with
 * worker progress, as for other UCP worker internal data structures. */
static void ucp_sched_make_ready(ucp_sched_h sched, ucp_sched_task_t *task)
{
  if ((task->flags & (UCP_SCHED_TASK_READY | UCP_SCHED_TASK_STARTED |
                      UCP_SCHED_TASK_COMPLETED | UCP_SCHED_TASK_FAILED)) ||
      ((task->remaining_deps != 0) &&
       !(task->flags & UCP_SCHED_TASK_OFFLOADED))) {
    return;
  }

  ucs_assert(task->start != NULL);
  task->flags |= UCP_SCHED_TASK_READY;
  ucs_list_add_tail(&sched->ready, &task->ready_elem);
}

/* This keeps the exact half-open interval semantics without integer overflow. */
int ucp_sched_check_overlap(const void *a_buf, size_t a_size, const void *b_buf,
                            size_t b_size)
{
  uintptr_t a = (uintptr_t)a_buf;
  uintptr_t b = (uintptr_t)b_buf;

  if ((a_size == 0) || (b_size == 0)) {
    return 0;
  }

  return (a <= b) ? ((b - a) < a_size) : ((a - b) < b_size);
}

/*
 * Preserve the original dependency semantics:
 *   - a send depends on a prior receive overlapping its source buffer;
 *   - a send depends on a prior send with the same EP/tag when that send is
 *     not offloaded;
 *   - a send depends on a prior write operation when its local source buffer
 *     overlaps the prior operation's recorded destination address.
 *
 * The third rule is only meaningful when both addresses belong to the same
 * comparable address space, as in the original implementation.
 */
static int ucp_sched_depends_on(const ucp_sched_task_t *task,
                                const ucp_sched_task_t *prev)
{
  if (ucp_sched_check_overlap(task->in, task->size, prev->out, prev->size)) {
    return 1;
  }

  if ((task->type == UCP_SCHED_TASK_SEND) &&
      (prev->type == UCP_SCHED_TASK_SEND) && (task->ep == prev->ep) &&
      (task->tag == prev->tag) && !(prev->flags & UCP_SCHED_TASK_OFFLOADED)) {
    return 1;
  }

  return 0;
}

static ucs_status_t ucp_sched_offload_send(ucp_sched_h       sched,
                                           ucp_sched_task_t *task)
{
  ucp_sched_edge_t   *edge;
  ucp_worker_iface_t *wiface;
  size_t              count = 0;
  size_t              capacity;
  uct_gop_h          *new_gops;

  if (task->remaining_deps > sched->gops_capacity) {
    capacity = (sched->gops_capacity == 0) ? 8 : sched->gops_capacity;
    while (capacity < task->remaining_deps) {
      if (capacity > SIZE_MAX / 2) {
        capacity = task->remaining_deps;
        break;
      }
      capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*sched->gops)) {
      return UCS_ERR_NO_MEMORY;
    }
    new_gops = ucs_realloc(sched->gops, capacity * sizeof(*sched->gops),
                           "schedule gop scratch");
    if (new_gops == NULL) {
      return UCS_ERR_NO_MEMORY;
    }
    sched->gops          = new_gops;
    sched->gops_capacity = capacity;
  }

  ucs_list_for_each (edge, &task->predecessors, to_link) {
    /* Completed predecessors still appear in the persistent DAG, but
     * require no device-side wait. */
    if (edge->from->flags & UCP_SCHED_TASK_COMPLETED) {
      continue;
    }
    ucs_assert(edge->from->flags & UCP_SCHED_TASK_OFFLOADED);
    sched->gops[count++] = edge->from->comph;
  }
  ucs_assert(count == task->remaining_deps);

  wiface = sched->worker->tm.offload.iface;
  ucs_assert(wiface != NULL);

  /* Preserve the existing release heuristic; transport-specific ownership
   * still needs a separate review before this can be considered generic. */
  if (count > 1) {
    task->flags |= UCP_SCHED_TASK_RELEASE_SCHED;
  }

  return uct_iface_tag_sched_send(wiface->iface, &task->comph, sched->gops,
                                  count);
}

ucs_status_t ucp_sched_task_recv(ucp_sched_h schedh, ucp_sched_task_t *task)
{
  ucp_request_t      *req = task->req;
  ucp_worker_iface_t *wiface;
  ucs_status_t        status;

  ucs_assert(sched != NULL);

  if ((req->recv.op_attr & UCP_OP_ATTR_FLAG_OP_OFFLOAD) &&
      !(schedh->flags & UCP_SCHED_OFFLOAD_ENABLED)) {
    return UCS_ERR_INVALID_PARAM;
  }

  if ((schedh->flags & UCP_SCHED_OFFLOAD_ENABLED) &&
      (req->flags & UCP_REQUEST_FLAG_OFFLOADED)) {
    wiface = schedh->worker->tm.offload.iface;
    status = uct_iface_tag_sched_recv(wiface->iface, &req->recv.uct_ctx,
                                      &task->comph);
    if (status != UCS_OK) {
      ucp_sched_task_unalloc(schedh, task);
      return status;
    }
    task->flags |= UCP_SCHED_TASK_OFFLOADED | UCP_SCHED_TASK_RELEASE_SCHED;
  }

  ucs_list_add_tail(&schedh->schedule, &task->elem);
  req->task   = task;
  req->flags |= UCP_REQUEST_FLAG_SCHEDULED;

  ucp_trace_req(req, "scheduled recv task %p. region %p..%p", task, task->out,
                UCS_PTR_BYTE_OFFSET(task->out, task->size));
  return UCS_OK;
}

/* Wrapper is called by ucp_request_send already. */
ucs_status_t ucp_sched_progress_wrapper(uct_pending_req_t *self)
{
  ucp_request_t     *req   = ucs_container_of(self, ucp_request_t, send.uct);
  const ucp_proto_t *proto = req->send.proto_config->proto;
  ucp_sched_task_t  *task  = req->task;

  if (!(task->flags & UCP_SCHED_TASK_READY)) {
    ucp_trace_req(req, "scheduled task %p type %s not ready", task,
                  ucp_sched_type_to_str[task->type]);
    return UCS_OK;
  }

  ucs_list_del(&task->ready_elem);
  task->flags &= ~UCP_SCHED_TASK_READY;
  task->flags |= UCP_SCHED_TASK_STARTED;

  if (req->send.ep->worker->context->config.progress_wrapper_enabled) {
    req->send.uct.func = ucp_request_progress_wrapper;
  } else {
    req->send.uct.func = proto->progress[req->send.proto_stage];
  }

  ucp_trace_req(req, "scheduled send task %p can be progressed", req->task);
  return req->send.uct.func(self);
}

ucs_status_t ucp_sched_task_send(ucp_sched_h schedh, ucp_sched_task_t *task)
{
  ucp_request_t    *req = task->req;
  ucp_sched_task_t *prev;
  ucs_status_t      status;
  int               can_offload = 1;

  ucs_assert(sched != NULL);

  /* Build incoming DAG edges to all earlier conflicting operations. */
  ucp_trace_req(req, "send task %p, region %p..%p", task, task->in,
                UCS_PTR_BYTE_OFFSET(task->in, task->size));
  ucs_list_for_each (prev, &schedh->schedule, elem) {
    if (!ucp_sched_depends_on(task, prev)) {
      continue;
    }

    ucp_trace_req(req, "\tdepends on. task=%p, type=%s, region %p..%p", prev,
                  ucp_sched_type_to_str[prev->type], prev->out,
                  UCS_PTR_BYTE_OFFSET(prev->out, prev->size));

    status = ucp_sched_edge_add(schedh, prev, task);
    if (status != UCS_OK) {
      goto err_edges;
    }
    if (!(prev->flags &
          (UCP_SCHED_TASK_OFFLOADED | UCP_SCHED_TASK_COMPLETED))) {
      can_offload = 0;
    }
  }

  /* The transport GOP API takes an int dependency count. Keep the host
   * DAG unlimited, falling back to software beyond that transport limit. */
  if ((task->remaining_deps != 0) && can_offload &&
      (task->remaining_deps <= INT_MAX) &&
      (schedh->flags & UCP_SCHED_OFFLOAD_ENABLED)) {
    status = ucp_sched_offload_send(schedh, task);
    if (status != UCS_OK) {
      goto err_edges;
    }
    task->flags |= UCP_SCHED_TASK_OFFLOADED;
  }

  ucs_list_add_tail(&schedh->schedule, &task->elem);
  req->task           = task;
  req->flags         |= UCP_REQUEST_FLAG_SCHEDULED;
  req->send.uct.func  = ucp_sched_progress_wrapper;

  ucp_trace_req(req, "scheduled send task %p, %zu dependencies, %zu remaining",
                task, task->num_deps, task->remaining_deps);
  ucp_sched_make_ready(schedh, task);
  return UCS_OK;

err_edges:
  ucp_sched_remove_incoming(schedh, task);
  ucp_sched_task_unalloc(schedh, task);
  return status;
}

/* Called at *actual UCP request completion*, not when the first protocol
 * progress function returns and not merely when a send is posted to UCT. */
ucs_status_t ucp_sched_task_remove(ucp_sched_task_t *task)
{
  ucp_request_t    *req   = task->req;
  ucp_sched_h       sched = task->schedh;
  ucp_sched_edge_t *edge;

  ucs_assert(req->flags & UCP_REQUEST_FLAG_SCHEDULED);

  /* A request may be canceled before its start callback ran. */
  if (task->flags & UCP_SCHED_TASK_READY) {
    ucs_list_del(&task->ready_elem);
    task->flags &= ~UCP_SCHED_TASK_READY;
  }

  /* A failed request must not release dependents as though its buffer were
   * correctly produced. Error propagation/cancellation is a separate policy. */
  if (req->status != UCS_OK) {
    task->flags |= UCP_SCHED_TASK_FAILED;
    ucs_error("SCHED: task %p failed (%s); dependents remain blocked", task,
              ucs_status_string(req->status));
  } else {
    task->flags |= UCP_SCHED_TASK_COMPLETED;
    ucs_list_for_each (edge, &task->successors, from_link) {
      ucs_assert(edge->to->remaining_deps > 0);
      --edge->to->remaining_deps;
      if (edge->to->remaining_deps == 0) {
        ucp_sched_make_ready(sched, edge->to);
      }
    }
  }

  /* Keep the node and graph edges, but discard the request pointer. */
  task->req   = NULL;
  req->task   = NULL;
  req->flags &= ~UCP_REQUEST_FLAG_SCHEDULED;
  return UCS_OK;
}

static void ucp_sched_destroy(ucp_sched_h sched)
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
    if (task->flags & UCP_SCHED_TASK_RELEASE_SCHED) {
      uct_iface_tag_sched_release(sched->worker->tm.offload.iface->iface,
                                  task->comph);
    }

    ucs_list_for_each_safe (edge, tmp_edge, &task->successors, from_link) {
      ucp_sched_edge_del(sched, edge);
    }
  }

  ucs_list_for_each_safe (task, tmp_task, &sched->schedule, elem) {
    if (task->flags & UCP_SCHED_TASK_READY) {
      ucs_list_del(&task->ready_elem);
    }
    ucs_list_del(&task->elem);
    ucs_assert(ucs_list_is_empty(&task->predecessors));
    ucs_assert(ucs_list_is_empty(&task->successors));
    ucs_mpool_put_inline(task);
  }

  ucs_mpool_cleanup(&sched->edge_mp, 1);
  ucs_mpool_cleanup(&sched->task_mp, 1);
  ucs_free(sched->gops);
  ucs_mpool_put(sched);
}

unsigned ucp_sched_progress_cb(void *arg)
{
  ucs_status_t       status;
  ucp_sched_h        sched = arg;
  ucp_sched_task_t  *task;
  ucp_request_t     *req;
  unsigned           progressed = 0;
  const ucp_proto_t *proto;

  ucs_assert(!sched->progressing);
  sched->progressing = 1;

  while (!ucs_list_is_empty(&sched->ready) &&
         (progressed < UCP_SCHED_PROGRESS_BUDGET) && !sched->closing) {
    task = ucs_list_extract_head(&sched->ready, ucp_sched_task_t, ready_elem);
    task->flags &= ~UCP_SCHED_TASK_READY;
    task->flags |= UCP_SCHED_TASK_STARTED;

    req   = task->req;
    proto = req->send.proto_config->proto;

    /* A start callback can synchronously complete a request, append ready
     * tasks, or even request schedule destruction. Never access task/req
     * after the callback without revalidating the scheduler lifecycle. */
    ucp_trace_req(task->req, "scheduler starting scheduled task %p", task);

    /* Call ucp_sched_progress_wrapper. */
    if (req->send.ep->worker->context->config.progress_wrapper_enabled) {
      req->send.uct.func = ucp_request_progress_wrapper;
    } else {
      req->send.uct.func = proto->progress[req->send.proto_stage];
    }

    status = req->send.uct.func(&req->send.uct);
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

  sched->flags         = 0;
  sched->count         = 0;
  sched->worker        = worker;
  sched->gops          = NULL;
  sched->gops_capacity = 0;
  sched->progress_id   = UCS_CALLBACKQ_ID_NULL;
  sched->progressing   = 0;
  sched->closing       = 0;
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

  if (worker->tm.offload.iface != NULL) {
    sched->flags |= UCP_SCHED_OFFLOAD_ENABLED;
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
