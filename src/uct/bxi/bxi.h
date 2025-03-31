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
  UCT_BXI_OP_AM_BCOPY = 0,
  UCT_BXI_OP_BLOCK,
} uct_bxi_op_type_t;

#define uct_bxi_rc_log(rc)                                                     \
  switch (rc) {                                                                \
  case PTL_FAIL:                                                               \
    ucs_error("BXI: error PTL_FAIL");                                          \
    break;                                                                     \
  case PTL_ARG_INVALID:                                                        \
    ucs_error("BXI: error PTL_ARG_INVALID");                                   \
    break;                                                                     \
  case PTL_NO_SPACE:                                                           \
    ucs_error("BXI: error PTL_NO_SPACE");                                      \
    break;                                                                     \
  case PTL_NO_INIT:                                                            \
    ucs_error("BXI: error PTL_NO_INIT");                                       \
    break;                                                                     \
  default:                                                                     \
    ucs_error("BXI: unknown BXI error.");                                      \
    break;                                                                     \
  }

#define uct_bxi_wrap(_bxi_call)                                                \
  ({                                                                           \
    ucs_status_t loc_rc = UCS_OK;                                              \
    int          bxi_rc;                                                       \
    if ((bxi_rc = _bxi_call) != PTL_OK) {                                      \
      uct_bxi_rc_log(bxi_rc);                                                  \
      loc_rc = UCS_ERR_IO_ERROR;                                               \
    }                                                                          \
    loc_rc;                                                                    \
  })

#define UCT_BXI_CHECK_TAG(_ptl_iface)                                          \
  if (ucs_unlikely((_ptl_iface)->tm.num_tags == 0)) {                          \
    return UCS_ERR_EXCEEDS_LIMIT;                                              \
  }

extern uct_component_t uct_bxi_component;

#endif
