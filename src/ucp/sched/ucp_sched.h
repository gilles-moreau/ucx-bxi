#ifndef UCP_SCHED_H_
#define UCP_SCHED_H_

#include <ucp/api/ucp.h>
#include <uct/api/uct.h>

#include <ucs/datastruct/list.h>
#include <ucs/datastruct/mpool.h>
#include <ucs/debug/assert.h>
#include <ucs/debug/log.h>

typedef struct ucp_request    ucp_request_t;
typedef struct ucp_sched_task ucp_sched_task_t;
typedef struct ucp_sched_edge ucp_sched_edge_t;
typedef struct ucp_sched      ucp_sched_t;

typedef enum ucp_sched_task_type {
  UCP_SCHED_TASK_TYPE_SEND,
  UCP_SCHED_TASK_TYPE_RECV,
  UCP_SCHED_TASK_TYPE_PUT,
  UCP_SCHED_TASK_TYPE_GET,
  UCP_SCHED_TASK_TYPE_AMO,
  UCP_SCHED_TASK_TYPE_LAST,
} ucp_sched_task_type_t;

enum {
  UCP_SCHED_TASK_FLAG_OFFLOADED     = UCS_BIT(0),
  UCP_SCHED_TASK_FLAG_RELEASE_SCHED = UCS_BIT(1),
  UCP_SCHED_TASK_FLAG_COMPLETED     = UCS_BIT(2),
  UCP_SCHED_TASK_FLAG_READY         = UCS_BIT(3),
  UCP_SCHED_TASK_FLAG_STARTED       = UCS_BIT(4),
  UCP_SCHED_TASK_FLAG_FAILED        = UCS_BIT(5)
};

struct ucp_sched_edge {
  ucp_sched_task_t *from;
  ucp_sched_task_t *to;
  ucs_list_link_t   from_link; /* In from->successors */
  ucs_list_link_t   to_link;   /* In to->predecessors */
};

typedef struct ucp_sched_task_ops {
  ucs_status_t (*init)(ucp_request_t *req, ucp_sched_task_t **task_p);
  ucs_status_ptr_t (*commit)(ucp_sched_task_t *task);
  ucs_status_t (*progress)(ucp_sched_task_t *task);
  ucs_status_t (*complete)(ucp_sched_task_t *task);
} ucp_sched_task_ops_t;

struct ucp_sched_task {
  ucp_sched_t          *sched; /* Schedule the task belongs to */
  unsigned              flags;
  ucp_sched_task_ops_t  ops;
  ucp_sched_task_type_t type;
  void                 *in;   /* Input buffer */
  void                 *out;  /* Ouput buffer */
  size_t                size; /* Buffer size */
  ucp_ep_h              ep;

  ucp_request_t *req;   /* Request associated with the task */
  uct_gop_h      comph; /* Task's operation completion handle */

  struct {
    ucp_tag_t           tag, tag_mask;
    ucp_request_param_t param;
    size_t              count;
    void               *buffer;
  } recv;

  ucs_list_link_t elem;         /* All tasks, insertion order */
  ucs_list_link_t ready_elem;   /* Only while READY */
  ucs_list_link_t predecessors; /* Incoming edges */
  ucs_list_link_t successors;   /* Outgoing edges */

  size_t num_deps;       /* Total graph in-degree */
  size_t remaining_deps; /* Not-yet-completed predecessors */
};

typedef struct ucp_sched {
  unsigned     flags;
  size_t       count;
  ucp_worker_h worker;

  ucs_list_link_t schedule; /* All tasks, including completed */
  ucs_list_link_t ready;    /* Eligible, not yet started */

  ucs_mpool_t task_mp;
  ucs_mpool_t edge_mp;

  int      progress_id;
  unsigned progressing;
  unsigned closing;
} ucp_sched_t;

ucs_status_t     ucp_sched_task_init(ucp_sched_h schedh, ucp_request_t *req,
                                     ucp_sched_task_type_t type, void *in,
                                     void *out, size_t size, ucp_ep_h ep,
                                     ucp_sched_task_t **task_p);
ucs_status_ptr_t ucp_sched_task_schedule(ucp_sched_task_t *task);
ucs_status_t     ucp_sched_task_fini(ucp_sched_task_t *task);
unsigned         ucp_sched_progress_cb(void *arg);

/* Public API */
ucs_status_t ucp_sched_create(ucp_worker_h worker, ucp_sched_h *sched_p);
void         ucp_sched_fini(ucp_sched_h sched);

#endif
