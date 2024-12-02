#ifndef PTL_EP_H
#define PTL_EP_H

#include "ptl_iface.h"

#include <ucs/debug/debug_int.h>
#include <uct/api/uct.h>

extern ptl_op_t uct_ptl_atomic_op_table[];

enum {
  UCT_PTL_EP_CONN_CONNECTED,
  UCT_PTL_EP_CONN_PT_DISABLED,
};

typedef struct uct_ptl_ep_config {
  int id;
} uct_ptl_ep_config_t;

typedef struct uct_ptl_ep {
  uct_base_ep_t super;
  struct {
    int id;
  } config;
  uct_ptl_device_addr_t dev_addr;
  uint8_t conn_state;
} uct_ptl_ep_t;

typedef struct uct_ptl_ep_pending_req {
  uct_pending_req_t super;
  uct_ptl_ep_t *ep;
} uct_ptl_ep_pending_req_t;

typedef struct uct_ptl_ep_pending_purge_arg {
  uct_pending_purge_callback_t cb;
  void *arg;
} uct_ptl_ep_pending_purge_arg_t;

UCS_CLASS_DECLARE(uct_ptl_ep_t, uct_ptl_iface_t *, const uct_ep_params_t *);

#endif
