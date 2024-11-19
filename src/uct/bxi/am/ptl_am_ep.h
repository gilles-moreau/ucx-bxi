#ifndef PTL_AM_EP_H
#define PTL_AM_EP_H

#include <ecr/portals/base/ptl_ep.h>
#include <ecr/portals/ptl_types.h>

typedef struct ecr_ptl_am_ep_config {
    int id;
} ecr_ptl_am_ep_config_t;

typedef struct ecr_ptl_am_ep {
    ecr_ptl_ep_t super;
    struct {
        int id;
    } config;
    ptl_pt_index_t am_pti;
    ptl_pt_index_t rma_pti;
    ecc_mpool_t   *am_mp;
    ecc_mpool_t   *rma_mp;
    ecr_ptl_md_t  *am_md;
    ecr_ptl_md_t  *rma_md;
} ecr_ptl_am_ep_t;

ssize_t ecr_ptl_send_am_bcopy(ecr_ep_h ep, uint8_t id, ecr_pack_callback_t pack,
                              void *arg, unsigned flags);
ecc_status_t ecr_ptl_send_am_zcopy(ecr_ep_h ep, uint8_t id, void *header,
                                   unsigned            header_length,
                                   const struct iovec *iov, size_t iovcnt,
                                   unsigned flags, ecr_completion_t *comp);
ecc_status_t ecr_ptl_am_put_zcopy(ecr_ep_h ep, uint64_t local_addr,
                                  uint64_t remote_addr, ecr_mr_h mr,
                                  ecr_rkey_h rkey, size_t size,
                                  ecr_completion_t *comp);
ecc_status_t ecr_ptl_am_get_zcopy(ecr_ep_h ep, uint64_t local_addr,
                                  uint64_t remote_addr, ecr_mr_h mr,
                                  ecr_rkey_h rkey, size_t size,
                                  ecr_completion_t *comp);
ecc_status_t ecr_ptl_create_am_ep(ecr_iface_h iface, ecr_iface_addr_t *addr,
                                  unsigned flags, ecr_ep_h *ep_p);
ecc_status_t ecr_ptl_delete_am_ep(ecr_ep_h ep);

#endif
