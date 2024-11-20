#ifndef PTL_EP_H
#define PTL_EP_H

#include "ptl_iface.h"

#include <ucs/debug/debug_int.h>
#include <uct/api/uct.h>

typedef struct uct_ptl_ep_config {
  int id;
} uct_ptl_ep_config_t;

typedef struct uct_ptl_ep {
  uct_base_ep_t super;
  struct {
    int id;
  } config;
  ptl_process_t pid;
} uct_ptl_ep_t;

UCS_CLASS_DECLARE(uct_ptl_ep_t, uct_ptl_iface_t *, const uct_ep_params_t *);
#endif
