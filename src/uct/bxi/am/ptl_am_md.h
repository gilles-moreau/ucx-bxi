#ifndef PTL_AM_MS_H
#define PTL_AM_MS_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ecr/portals/base/ptl_ms.h>
#include <ecr/portals/ptl_types.h>

typedef struct ecr_ptl_am_mr {
    ecr_ptl_mr_t  super;
    ecr_ptl_md_t *md;
    ecr_ptl_me_t *me;
} ecr_ptl_am_mr_t;

typedef struct ecr_ptl_am_rkey {
    ecr_ptl_rkey_t super;
} ecr_ptl_am_rkey_t;

typedef struct ecr_ptl_am_ms_config {
    ecr_ptl_ms_config_t super;
} ecr_ptl_am_ms_config_t;

typedef struct ecr_ptl_am_ms {
    ecr_ptl_ms_t super;
    struct {
        size_t id;
    } config;
    ecr_ptl_md_t md;
    ecr_ptl_me_t me;
} ecr_ptl_am_ms_t;

#endif
