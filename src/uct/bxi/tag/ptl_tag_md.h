#ifndef PTL_TAG_MS_H
#define PTL_TAG_MS_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ecr/portals/base/ptl_ms.h>
#include <ecr/portals/ptl_types.h>

typedef struct ecr_ptl_tag_mr {
    ecr_ptl_mr_t  super;
    ecr_ptl_md_t *md;
    ecr_ptl_me_t  me;
} ecr_ptl_tag_mr_t;

typedef struct ecr_ptl_tag_rkey {
    ecr_ptl_rkey_t   super;
    ptl_match_bits_t match;
    uint64_t         offset;
} ecr_ptl_tag_rkey_t;

typedef struct ecr_ptl_tag_ms_config {
    ecr_ptl_ms_config_t super;
} ecr_ptl_tag_ms_config_t;

typedef struct ecr_ptl_tag_ms {
    ecr_ptl_ms_t super;
    struct {
        size_t id;
    } config;
    ecr_ptl_md_t md;
    ptl_size_t   me_mb;
} ecr_ptl_tag_ms_t;

#endif
