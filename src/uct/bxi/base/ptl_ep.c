#include "ptl_ep.h"

UCS_CLASS_INIT_FUNC(uct_ptl_ep_t, uct_ptl_iface_t *iface,
                    const uct_ep_params_t *params) {
  uct_ptl_iface_t *ptl_iface = ucs_derived_of(iface, uct_ptl_iface_t);

  UCS_CLASS_CALL_SUPER_INIT(uct_base_ep_t, &iface->super);

  self->pid = uct_ptl_iface_md(ptl_iface)->pid;

  return UCS_OK;
}

static UCS_CLASS_CLEANUP_FUNC(uct_ptl_ep_t) {
  ucs_debug("destroy ptl ep %p", self);
}

UCS_CLASS_DEFINE(uct_ptl_ep_t, uct_ep_t);
