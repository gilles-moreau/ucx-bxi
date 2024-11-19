#ifndef PTL_IFACE_H
#define PTL_IFACE_H

#include "ptl_ms.h"

#include <ecr/portals/ptl_types.h>
#include <ecr/base/ecr_iface.h>
#include <ecc/type/class.h>
#include <ecc/datastruct/queue.h>
#include <ecc/datastruct/khash.h>

typedef ecc_status_t (*handle_ev_func_t)(ecr_ptl_iface_t *iface,
                                         ptl_event_t     *ev);

typedef struct ecr_ptl_iface_addr {
    ecr_iface_addr_t super;
    ptl_process_t    pid;
} ecr_ptl_iface_addr_t;

typedef struct ecr_ptl_iface_ops {
    handle_ev_func_t handle_ev;
} ecr_ptl_iface_ops_t;

typedef struct ecr_ptl_iface_config {
    ecr_iface_config_t super;
    size_t             max_events;
    int                max_outstanding_ops;
    int                copyin_buf_per_block;
    int                min_copyin_buf;
    int                max_copyin_buf;
    int                num_eager_blocks;
    int                eager_block_size;
    unsigned           features;
} ecr_ptl_iface_config_t;

typedef struct ecr_ptl_iface {
    ecr_iface_t super;
    struct {
        size_t          max_events;
        int             max_outstanding_ops;
        int             copyin_buf_per_block;
        int             min_copyin_buf;
        int             max_copyin_buf;
        int             num_eager_blocks;
        int             max_iovecs;
        size_t          eager_block_size;
        size_t          max_msg_size;
        size_t          max_atomic_size;
        ptl_ni_limits_t limits;
        unsigned        features;
    } config;
    ecr_ptl_iface_ops_t ops;
    ptl_handle_eq_t     eqh; // Event Queue
    ecc_list_elem_t     mds; // Memory descriptors
} ecr_ptl_iface_t;

ECC_CLASS_DECLARE_INIT_FUNC(ecr_ptl_iface_t, ecr_ms_h ms, ecr_device_t *device,
                            ecr_ptl_iface_config_t *config);
ECC_CLASS_DECLARE_CLEAN_FUNC(ecr_ptl_iface_t);
ECC_CLASS_DECLARE(ecr_ptl_iface_t);

ecc_status_t ecr_ptl_query_devices(ecr_component_h component,
                                   ecr_device_t  **devices_p,
                                   unsigned int   *num_devices_p);
ecc_status_t ecr_ptl_iface_progress(ecr_iface_h super);
void         ecr_ptl_iface_get_attr(ecr_iface_h iface, ecr_iface_attr_t *attr);
ecc_status_t ecr_ptl_md_progress(ecr_ptl_md_t *md);

static inline void
ecr_ptl_iface_enable_progression(ecr_ptl_iface_t *iface, ecr_ptl_md_t *md)
{
    ecc_list_push_head(&iface->mds, &md->elem);
}

static inline void ecr_ptl_iface_disable_progression(ecr_ptl_md_t *md)
{
    ecc_list_del(&md->elem);
}


extern ecc_config_tab_t ecr_ptl_iface_config_tab;
extern char            *ecr_ptl_event_str[];

// FIXME: this triggers a clang include not used error, check other solution
#define ecr_ptl_iface_ms(_iface)                                               \
    (ecc_derived_of((_iface)->super.ms, ecr_ptl_ms_t))

#endif
