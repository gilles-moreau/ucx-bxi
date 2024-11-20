#ifndef PTL_AM_EP_H
#define PTL_AM_EP_H

#include <uct/bxi/base/ptl_ep.h>

typedef struct uct_ptl_am_ep_config {
  int id;
} uct_ptl_am_ep_config_t;

typedef struct uct_ptl_am_ep {
  uct_ptl_ep_t super;
  struct {
    int id;
  } config;
  ptl_pt_index_t am_pti;
  ptl_pt_index_t rma_pti;
  ucs_mpool_t *am_mp;
  ucs_mpool_t *rma_mp;
  uct_ptl_md_t *am_md;
  uct_ptl_md_t *rma_md;
} uct_ptl_am_ep_t;

ssize_t uct_ptl_send_am_bcopy(uct_ep_h ep, uint8_t id, uct_pack_callback_t pack,
                              void *arg, unsigned flags);
ucs_status_t uct_ptl_send_am_zcopy(uct_ep_h ep, uint8_t id, void *header,
                                   unsigned header_length,
                                   const struct iovec *iov, size_t iovcnt,
                                   unsigned flags, uct_completion_t *comp);
ucs_status_t uct_ptl_am_put_zcopy(uct_ep_h ep, uint64_t local_addr,
                                  uint64_t remote_addr, uct_mem_h memh,
                                  uct_rkey_t rkey, size_t size,
                                  uct_completion_t *comp);
ucs_status_t uct_ptl_am_get_zcopy(uct_ep_h ep, uint64_t local_addr,
                                  uint64_t remote_addr, uct_mem_h memh,
                                  uct_rkey_t rkey, size_t size,
                                  uct_completion_t *comp);
ucs_status_t uct_ptl_create_am_ep(uct_iface_h iface, uct_iface_addr_t *addr,
                                  unsigned flags, uct_ep_h *ep_p);
ucs_status_t uct_ptl_delete_am_ep(uct_ep_h ep);

#endif
