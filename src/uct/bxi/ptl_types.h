#ifndef PTL_TYPES_H
#define PTL_TYPES_H

#include <uct/base/uct_md.h>

#include <ucs/datastruct/mpool.h>
#include <ucs/datastruct/queue.h>
#include <ucs/debug/log.h>
#include <ucs/debug/memtrack_int.h>

#include <limits.h>
#include <sys/uio.h>

#include <portals4.h>

/*********************************/
/********** Forward Decl *********/
/*********************************/
typedef struct uct_ptl_iface uct_ptl_iface_t;
typedef struct uct_ptl_wp uct_ptl_wp_t;
typedef struct uct_ptl_rq uct_ptl_rq_t;
typedef struct uct_ptl_md uct_ptl_md_t;

/*********************************/
/********** PTL TYPES   **********/
/*********************************/
#define UCT_PTL_PT_NULL ((ptl_pt_index_t) - 1)

/* Operation types. */
typedef enum {
  /* Block operation. */
  UCT_PTL_OP_BLOCK,
  /* Tag Matching operations. */
  UCT_PTL_OP_RECV,
  UCT_PTL_OP_TAG_ZCOPY,
  UCT_PTL_OP_TAG_SEARCH,
  /* RMA operations. */
  UCT_PTL_OP_RMA_PUT,
  UCT_PTL_OP_RMA_GET_ZCOPY,
  UCT_PTL_OP_RMA_GET_BCOPY,
  UCT_PTL_OP_RMA_FLUSH,
  /* Atomic operations. */
  UCT_PTL_OP_ATOMIC_POST,
  UCT_PTL_OP_ATOMIC_FETCH,
  UCT_PTL_OP_ATOMIC_CSWAP,
#if defined(MPC_USE_PORTALS_CONTROL_FLOW)
  /* Token operations. */
  UCT_PTL_OP_TK_INIT,
  UCT_PTL_OP_TK_REQUEST,
  UCT_PTL_OP_TK_GRANT,
  UCT_PTL_OP_TK_RELEASE,
#endif
} uct_ptl_op_type_t;

typedef struct uct_ptl_op {
  int64_t id;             /* Operation identifier. */
  uct_ptl_op_type_t type; /* Type of operation */
  uct_completion_t *comp; /* Completion callback */
  ptl_size_t seqn;
  ucs_queue_elem_t elem;
  size_t size;
  union {
    struct {
      uct_tag_context_t *ctx;
      ptl_handle_me_t meh;
    } tag;
    struct {
      uct_unpack_callback_t unpack;
      void *arg;
    } get_bcopy;
    struct {
      uint64_t value;
      uint64_t compare;
    } ato;
  };

} uct_ptl_op_t;

#define uct_ptl_rc_log(rc)                                                     \
  switch (rc) {                                                                \
  case PTL_FAIL:                                                               \
    ucs_error("PTL: error PTL_FAIL");                                          \
    break;                                                                     \
  case PTL_ARG_INVALID:                                                        \
    ucs_error("PTL: error PTL_ARG_INVALID");                                   \
    break;                                                                     \
  case PTL_NO_SPACE:                                                           \
    ucs_error("PTL: error PTL_NO_SPACE");                                      \
    break;                                                                     \
  case PTL_NO_INIT:                                                            \
    ucs_error("PTL: error PTL_NO_INIT");                                       \
    break;                                                                     \
  default:                                                                     \
    ucs_error("PTL: unknown PTL error.");                                      \
    break;                                                                     \
  }

#define uct_ptl_wrap(_ptl_call)                                                \
  ({                                                                           \
    ucs_status_t loc_rc = UCS_OK;                                              \
    int ptl_rc;                                                                \
    if ((ptl_rc = _ptl_call) != PTL_OK) {                                      \
      uct_ptl_rc_log(ptl_rc);                                                  \
      loc_rc = UCS_ERR_IO_ERROR;                                               \
    }                                                                          \
    loc_rc;                                                                    \
  })

#define uct_ptl_iface_trace_am(_iface, _type, _am_id, _data, _length)          \
  uct_iface_trace_am(&(_iface)->super.super, _type, _am_id, _data, _length,    \
                     "%cX",                                                    \
                     ((_type) == UCT_AM_TRACE_TYPE_RECV)   ? 'R'               \
                     : ((_type) == UCT_AM_TRACE_TYPE_SEND) ? 'T'               \
                                                           : '?')

extern uct_component_t ptl_am_component;
extern uct_component_t ptl_rma_component;
extern uct_component_t ptl_tag_component;

#endif
