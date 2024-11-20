#ifndef PTL_AM_MS_H
#define PTL_AM_MS_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#define UCT_PTL_AM_CONFIG_PREFIX "PTL_AM"

#include <uct/bxi/base/ptl_md.h>

typedef struct uct_ptl_am_mr {
  uct_ptl_mr_t super;
  uct_ptl_mmd_t *mmd;
  uct_ptl_me_t *me;
} uct_ptl_am_mr_t;

typedef struct uct_ptl_am_rkey {
  uct_ptl_rkey_t super;
} uct_ptl_am_rkey_t;

typedef struct uct_ptl_am_md_config {
  uct_ptl_md_config_t super;
} uct_ptl_am_md_config_t;

typedef struct uct_ptl_am_md {
  uct_ptl_md_t super;
  struct {
    size_t id;
  } config;
  uct_ptl_mmd_t mmd;
  uct_ptl_me_t me;
} uct_ptl_am_md_t;

#endif
