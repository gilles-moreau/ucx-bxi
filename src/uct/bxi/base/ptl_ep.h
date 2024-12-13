#ifndef PTL_EP_H
#define PTL_EP_H

#include "ptl_iface.h"

#include <ucs/debug/debug_int.h>
#include <uct/api/uct.h>

extern ptl_op_t uct_ptl_atomic_op_table[];

enum {
  UCT_PTL_EP_CONN_CONNECTED,
  UCT_PTL_EP_CONN_CLOSED,
};

typedef struct uct_ptl_ep_config {
  int max_retries;
} uct_ptl_ep_config_t;

typedef struct uct_ptl_ep {
  uct_base_ep_t super;
  struct {
    int max_retries;
  } config;
  uct_ptl_device_addr_t dev_addr;
  ucs_mpool_t *ops_mp;
  ucs_mpool_t *copyin_mp;
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

ucs_status_t uct_ptl_ep_prepare_op(uct_ptl_op_type_t type, int get_buf,
                                   uct_completion_t *comp,
                                   uct_tag_context_t *ctx,
                                   uct_ptl_iface_t *iface, uct_ptl_ep_t *ep,
                                   uct_ptl_mmd_t *mmd, uct_ptl_op_t **op_p);
ucs_status_t uct_ptl_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *req,
                                    unsigned flags);
void uct_ptl_ep_pending_purge_cb(uct_pending_req_t *self, void *arg);
void uct_ptl_ep_pending_purge(uct_ep_h tl_ep, uct_pending_purge_callback_t cb,
                              void *arg);

#define uct_ptl_ep_iface(_ep, _type)                                           \
  ucs_derived_of((_ep)->super.super.super.iface, _type)
#endif
