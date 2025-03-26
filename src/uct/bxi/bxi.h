#ifndef BXI_TYPES_H
#define BXI_TYPES_H

#include <uct/base/uct_md.h>

#include <ucs/arch/atomic.h>
#include <ucs/datastruct/khash.h>
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
typedef struct uct_bxi_iface         uct_bxi_iface_t;
typedef struct uct_bxi_iface_send_op uct_bxi_iface_send_op_t;
typedef struct uct_bxi_ep            uct_bxi_ep_t;

/*********************************/
/********** BXI TYPES   **********/
/*********************************/
#define UCT_BXI_PT_NULL ((ptl_pt_index_t) - 1)

enum {
  UCT_BXI_OP_FLAG_OVERFLOW  = UCS_BIT(0),
  UCT_BXI_OP_FLAG_OFFLOADED = UCS_BIT(1),
};

/* Operation types. */
typedef enum {
  UCT_BXI_OP_AM_BCOPY,
} uct_bxi_op_type_t;

typedef struct uct_bxi_op {
  uct_bxi_op_type_t type; /* Type of operation */
  uct_completion_t *comp; /* Completion callback */
  ptl_pt_index_t    pti;
  uct_bxi_ep_t     *ep;
  uct_bxi_mmd_t    *mmd;
  void             *buffer;
  ptl_size_t        seqn;
  ucs_queue_elem_t  elem;
  size_t            size;
  union {
    struct {
      uct_tag_context_t *ctx;
      ptl_handle_me_t    meh;
      unsigned           flags;
      ptl_match_bits_t   tag;
      void              *buffer;
      unsigned           cancel;
      size_t             hdr_len;
    } tag;
    struct {
      uct_unpack_callback_t unpack;
      void                 *arg;
    } get_bcopy;
    struct {
      uint64_t value;
      uint64_t compare;
    } ato;
  };
} uct_bxi_op_t;

#define uct_bxi_rc_log(rc)                                                     \
  switch (rc) {                                                                \
  case BXI_FAIL:                                                               \
    ucs_error("BXI: error BXI_FAIL");                                          \
    break;                                                                     \
  case BXI_ARG_INVALID:                                                        \
    ucs_error("BXI: error BXI_ARG_INVALID");                                   \
    break;                                                                     \
  case BXI_NO_SPACE:                                                           \
    ucs_error("BXI: error BXI_NO_SPACE");                                      \
    break;                                                                     \
  case BXI_NO_INIT:                                                            \
    ucs_error("BXI: error BXI_NO_INIT");                                       \
    break;                                                                     \
  default:                                                                     \
    ucs_error("BXI: unknown BXI error.");                                      \
    break;                                                                     \
  }

#define uct_bxi_wrap(_bxi_call)                                                \
  ({                                                                           \
    ucs_status_t loc_rc = UCS_OK;                                              \
    int          bxi_rc;                                                       \
    if ((bxi_rc = _bxi_call) != BXI_OK) {                                      \
      uct_bxi_rc_log(bxi_rc);                                                  \
      loc_rc = UCS_ERR_IO_ERROR;                                               \
    }                                                                          \
    loc_rc;                                                                    \
  })

#define uct_bxi_wrap(_ptl_call)                                                \
  ({                                                                           \
    ucs_status_t loc_rc = UCS_OK;                                              \
    int          ptl_rc;                                                       \
    if ((ptl_rc = _ptl_call) != BXI_OK) {                                      \
      uct_bxi_rc_log(ptl_rc);                                                  \
      loc_rc = UCS_ERR_IO_ERROR;                                               \
    }                                                                          \
    loc_rc;                                                                    \
  })

#define UCT_BXI_CHECK_TAG(_ptl_iface)                                          \
  if (ucs_unlikely((_ptl_iface)->tm.num_tags == 0)) {                          \
    return UCS_ERR_EXCEEDS_LIMIT;                                              \
  }

#define uct_bxi_iface_trace_am(_iface, _type, _am_id, _data, _length)          \
  uct_iface_trace_am(&(_iface)->super.super, _type, _am_id, _data, _length,    \
                     "%cX",                                                    \
                     ((_type) == UCT_AM_TRACE_TYPE_RECV) ? 'R' :               \
                     ((_type) == UCT_AM_TRACE_TYPE_SEND) ? 'T' :               \
                                                           '?')

extern uct_component_t bxi_component;

#endif
