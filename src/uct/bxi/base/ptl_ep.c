#include "ptl_ep.h"

ptl_op_t uct_ptl_atomic_op_table[] = {
    [UCT_ATOMIC_OP_ADD] = PTL_SUM,   [UCT_ATOMIC_OP_AND] = PTL_BAND,
    [UCT_ATOMIC_OP_OR] = PTL_BOR,    [UCT_ATOMIC_OP_XOR] = PTL_BXOR,
    [UCT_ATOMIC_OP_SWAP] = PTL_SWAP, [UCT_ATOMIC_OP_CSWAP] = PTL_CSWAP,
};

UCS_CLASS_INIT_FUNC(uct_ptl_ep_t, uct_ptl_iface_t *iface,
                    const uct_ep_params_t *params) {
  UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super);

  self->dev_addr = *(uct_ptl_device_addr_t *)params->dev_addr;

  return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ptl_ep_t) {
  ucs_debug("destroy ptl ep %p", self);
}

UCS_CLASS_DEFINE(uct_ptl_ep_t, uct_ep_t);
