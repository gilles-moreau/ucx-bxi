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
  ucs_mpool_t *bcopy_mp;
  ucs_mpool_t *zcopy_mp;
  uct_ptl_mmd_t *am_mmd;
  uct_ptl_mmd_t *rma_mmd;
} uct_ptl_am_ep_t;

ucs_status_t uct_ptl_am_ep_put_short(uct_ep_h tl_ep, const void *buffer,
                                     unsigned length, uint64_t remote_addr,
                                     uct_rkey_t rkey);

ssize_t uct_ptl_am_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                                void *arg, uint64_t remote_addr,
                                uct_rkey_t rkey);

ucs_status_t uct_ptl_am_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                     size_t iovcnt, uint64_t remote_addr,
                                     uct_rkey_t rkey, uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_get_bcopy(uct_ep_h tl_ep,
                                     uct_unpack_callback_t unpack_cb, void *arg,
                                     size_t length, uint64_t remote_addr,
                                     uct_rkey_t rkey, uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_get_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                     size_t iovcnt, uint64_t remote_addr,
                                     uct_rkey_t rkey, uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t hdr,
                                    const void *buffer, unsigned length);

ucs_status_t uct_ptl_am_ep_am_short_iov(uct_ep_h ep, uint8_t id,
                                        const uct_iov_t *iov, size_t iovcnt);

ssize_t uct_ptl_am_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id,
                               uct_pack_callback_t pack_cb, void *arg,
                               unsigned flags);

ucs_status_t uct_ptl_am_ep_am_zcopy(uct_ep_h tl_ep, uint8_t id,
                                    const void *header, unsigned header_length,
                                    const uct_iov_t *iov, size_t iovcnt,
                                    unsigned flags, uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare,
                                          uint64_t swap, uint64_t remote_addr,
                                          uct_rkey_t rkey, uint64_t *result,
                                          uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_atomic64_post(uct_ep_h tl_ep, unsigned opcode,
                                         uint64_t value, uint64_t remote_addr,
                                         uct_rkey_t rkey);

ucs_status_t uct_ptl_am_ep_atomic64_fetch(uct_ep_h tl_ep,
                                          uct_atomic_op_t opcode,
                                          uint64_t value, uint64_t *result,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_flush(uct_ep_h tl_ep, unsigned flags,
                                 uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_fence(uct_ep_h tl_ep, unsigned flags);

void uct_ptl_am_ep_post_check(uct_ep_h tl_ep);

ucs_status_t uct_ptl_am_ep_get_address(uct_ep_h tl_ep, uct_ep_addr_t *addr);

int uct_ptl_am_ep_is_connected(const uct_ep_h tl_ep,
                               const uct_ep_is_connected_params_t *params);

ucs_status_t uct_ptl_am_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *n,
                                       unsigned flags);

void uct_ptl_am_ep_pending_purge(uct_ep_h ep, uct_pending_purge_callback_t cb,
                                 void *arg);

ucs_status_t uct_ptl_am_ep_check(uct_ep_h tl_ep, unsigned flags,
                                 uct_completion_t *comp);

UCS_CLASS_DECLARE(uct_ptl_am_ep_t, const uct_ep_params_t *);
UCS_CLASS_DECLARE_NEW_FUNC(uct_ptl_am_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DECLARE_DELETE_FUNC(uct_ptl_am_ep_t, uct_ep_t);
#endif
