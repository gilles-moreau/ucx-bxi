#ifndef UCP_SCHED_H_
#define UCP_SCHED_H_

#include <ucp/api/ucp_def.h>
#include <uct/api/uct_def.h>
#include <ucp/core/ucp_types.h> /* ucp_operation_id_t */

#include "ucp_types.h"

#include <ucs/datastruct/callbackq.h>
#include <ucs/datastruct/list.h>
#include <ucs/datastruct/mpool.h>

typedef struct ucp_request    ucp_request_t;
typedef struct ucp_sched_task ucp_sched_task_t;
typedef struct ucp_sched_edge ucp_sched_edge_t;

enum {
  UCP_SCHED_OFFLOAD_ENABLED = UCS_BIT(0)
};

typedef enum ucp_sched_task_type {
  UCP_SCHED_TASK_SEND,
  UCP_SCHED_TASK_RECV,
  UCP_SCHED_TASK_PUT,
  UCP_SCHED_TASK_GET,
  UCP_SCHED_TASK_AMO,
  UCP_SCHED_TASK_LAST,
} ucp_sched_task_type_t;

enum {
  UCP_SCHED_TASK_OFFLOADED     = UCS_BIT(0),
  UCP_SCHED_TASK_RELEASE_SCHED = UCS_BIT(1),
  UCP_SCHED_TASK_COMPLETED     = UCS_BIT(2),
  UCP_SCHED_TASK_READY         = UCS_BIT(8),
  UCP_SCHED_TASK_STARTED       = UCS_BIT(9),
  UCP_SCHED_TASK_FAILED        = UCS_BIT(10)
};

typedef ucs_status_ptr_t (*ucp_sched_recv_callback_t)(
        ucp_worker_h worker, void *buffer, size_t count, ucp_tag_t tag,
        ucp_tag_t tag_mask, ucp_request_param_t *param, ucp_request_t *req);

/*
 * Edge from predecessor to successor. An edge can be removed independently
 * of its neighbors, which makes a later transitive-reduction pass possible.
 */
struct ucp_sched_edge {
  ucp_sched_task_t *from;
  ucp_sched_task_t *to;
  ucs_list_link_t   from_link; /* In from->successors */
  ucs_list_link_t   to_link;   /* In to->predecessors */
};

/* A task address remains valid until the scheduler is destroyed. */
struct ucp_sched_task {
  ucp_sched_h           schedh;
  unsigned              flags;
  ucp_sched_task_type_t type;
  void                 *in;
  void                 *out;
  size_t                count;
  size_t                size;
  ucp_worker_h          worker;
  ucp_ep_h              ep;
  uct_gop_h             comph;

  /* Recv */
  ucp_request_param_t      *param;
  ucp_tag_t                 tag;
  ucp_tag_t                 tag_mask;
  ucp_sched_recv_callback_t cb;

  ucp_request_t *req;

  ucs_list_link_t elem;         /* All tasks, insertion order */
  ucs_list_link_t ready_elem;   /* Only while READY */
  ucs_list_link_t predecessors; /* Incoming edges */
  ucs_list_link_t successors;   /* Outgoing edges */

  size_t num_deps;       /* Total graph in-degree */
  size_t remaining_deps; /* Not-yet-completed predecessors */
};

typedef struct ucp_sched {
  unsigned     flags;
  ucp_worker_h worker;
  size_t       count;

  ucs_list_link_t schedule; /* All tasks, including completed */
  ucs_list_link_t ready;    /* Eligible, not yet started */

  /* Individually allocated, stable-address nodes and dependency edges. */
  ucs_mpool_t task_mp;
  ucs_mpool_t edge_mp;

  /* Reusable temporary array for transport offload dependency handles. */
  uct_gop_h *gops;
  size_t     gops_capacity;

  int      progress_id;
  unsigned progressing;
  unsigned closing;
} ucp_sched_t;

ucs_status_t ucp_sched_task_init(ucp_sched_h schedh, ucp_request_t *req,
                                 ucp_sched_task_type_t type, void *in,
                                 void *out, size_t count, ucp_ep_h ep,
                                 ucp_datatype_t dt, ucp_sched_task_t **task_p);
ucs_status_t ucp_sched_task_send(ucp_sched_h schedh, ucp_sched_task_t *task);
ucs_status_t ucp_sched_task_recv(ucp_sched_h schedh, ucp_sched_task_t *task);
ucs_status_t ucp_sched_task_remove(ucp_sched_task_t *task);

ucs_status_t ucp_sched_progress_wrapper(uct_pending_req_t *self);
ucs_status_t ucp_sched_create(ucp_worker_h worker, ucp_sched_h *sched_p);
void         ucp_sched_fini(ucp_sched_h sched);

#endif
