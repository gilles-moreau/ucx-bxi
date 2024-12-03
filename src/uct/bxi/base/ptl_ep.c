#include "ptl_ep.h"

ptl_op_t uct_ptl_atomic_op_table[] = {
    [UCT_ATOMIC_OP_ADD] = PTL_SUM,   [UCT_ATOMIC_OP_AND] = PTL_BAND,
    [UCT_ATOMIC_OP_OR] = PTL_BOR,    [UCT_ATOMIC_OP_XOR] = PTL_BXOR,
    [UCT_ATOMIC_OP_SWAP] = PTL_SWAP, [UCT_ATOMIC_OP_CSWAP] = PTL_CSWAP,
};

ucs_status_t uct_ptl_ep_prepare_op(uct_ptl_op_type_t type, int get_buf,
                                   uct_completion_t *comp, uct_ptl_ep_t *ep,
                                   uct_ptl_mmd_t *mmd, uct_ptl_op_t **op_p) {
  ucs_status_t rc = UCS_OK;
  uct_ptl_op_t *op;

  if (ep->conn_state == UCT_PTL_EP_CONN_CLOSED) {
    rc = UCS_ERR_TIMED_OUT;
    goto err;
  }

  op = ucs_mpool_get(ep->ops_mp);
  if (op == NULL) {
    rc = UCS_ERR_NO_RESOURCE;
    goto err;
  }
  op->comp = comp;
  op->ep = ep;
  op->mmd = mmd;
  op->type = type;
  op->buffer = NULL;
  if (get_buf) {
    op->buffer = ucs_mpool_get(ep->copyin_mp);
    if (op->buffer == NULL) {
      ucs_mpool_put(op);
      rc = UCS_ERR_NO_RESOURCE;
      goto err;
    }
  }

  *op_p = op;
err:
  return rc;
}

ucs_status_t uct_ptl_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *req,
                                    unsigned flags) {
  uct_ptl_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_ptl_iface_t);

  if (ucs_mpool_is_empty(&iface->ops_mp)) {
    return UCS_ERR_BUSY;
  }

  uct_pending_req_queue_push(&iface->pending_q, req);
  UCT_TL_EP_STAT_PEND(&ep->super);
  return UCS_OK;
}

void uct_ptl_ep_pending_purge_cb(uct_pending_req_t *self, void *arg) {
  uct_ptl_ep_pending_purge_arg_t *purge_arg = arg;

  purge_arg->cb(self, purge_arg->arg);
}

void uct_ptl_ep_pending_purge(uct_ep_h tl_ep, uct_pending_purge_callback_t cb,
                              void *arg) {
  uct_ptl_iface_t *iface = ucs_derived_of(tl_ep->iface, uct_ptl_iface_t);
  uct_pending_req_priv_queue_t UCS_V_UNUSED *priv;
  uct_ptl_ep_pending_purge_arg_t purge_arg;

  purge_arg.cb = cb;
  purge_arg.arg = arg;

  uct_pending_queue_purge(priv, &iface->pending_q, 1,
                          uct_ptl_ep_pending_purge_cb, &purge_arg);
}

UCS_CLASS_INIT_FUNC(uct_ptl_ep_t, uct_ptl_iface_t *iface,
                    const uct_ep_params_t *params) {
  UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super);

  self->dev_addr = *(uct_ptl_device_addr_t *)params->dev_addr;
  self->ops_mp = &iface->ops_mp;
  self->copyin_mp = &iface->copyin_mp;

  return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ptl_ep_t) {
  ucs_debug("destroy ptl ep %p", self);
}

UCS_CLASS_DEFINE(uct_ptl_ep_t, uct_ep_t);
