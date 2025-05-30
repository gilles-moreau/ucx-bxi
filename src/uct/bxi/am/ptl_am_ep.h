#ifndef PTL_AM_EP_H
#define PTL_AM_EP_H

#include "ptl_am_iface.h"

#include <uct/bxi/base/ptl_ep.h>

typedef struct uct_ptl_am_ep_config {
  int id;
} uct_ptl_am_ep_config_t;

typedef struct uct_ptl_am_ep {
  uct_ptl_ep_t super;
  struct {
    int id;
  } config;
  uct_ptl_am_iface_addr_t iface_addr;
  uct_ptl_mmd_t          *am_mmd;
  uct_ptl_mmd_t          *rma_mmd;
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

ucs_status_t uct_ptl_am_ep_get_bcopy(uct_ep_h              tl_ep,
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

ucs_status_t uct_ptl_am_ep_tag_eager_short(uct_ep_h ep, uct_tag_t tag,
                                           const void *data, size_t length);

ssize_t uct_ptl_am_ep_tag_eager_bcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                      uint64_t imm, uct_pack_callback_t pack_cb,
                                      void *arg, unsigned flags);

ucs_status_t uct_ptl_am_ep_tag_eager_zcopy(uct_ep_h ep, uct_tag_t tag,
                                           uint64_t imm, const uct_iov_t *iov,
                                           size_t iovcnt, unsigned flags,
                                           uct_completion_t *comp);

ucs_status_ptr_t uct_ptl_am_ep_tag_rndv_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                              const void      *header,
                                              unsigned         header_length,
                                              const uct_iov_t *iov,
                                              size_t iovcnt, unsigned flags,
                                              uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_tag_rndv_cancel(uct_ep_h tl_ep, void *tl_op);

ucs_status_t uct_ptl_am_ep_tag_rndv_request(uct_ep_h ep, uct_tag_t tag,
                                            const void *header,
                                            unsigned    header_length,
                                            unsigned    flags);

ucs_status_t uct_ptl_am_iface_tag_create_oop_ctx(uct_iface_h    tl_iface,
                                                 uct_oop_ctx_h *oop_ctx_p);
void         uct_ptl_am_iface_tag_delete_oop_ctx(uct_iface_h   tl_iface,
                                                 uct_oop_ctx_h tl_oop_ctx);

ucs_status_t uct_ptl_am_iface_tag_recv_zcopy(uct_iface_h tl_iface,
                                             uct_tag_t tag, uct_tag_t tag_mask,
                                             const uct_iov_t   *iov,
                                             size_t             iovcnt,
                                             uct_tag_context_t *ctx);

ucs_status_t uct_ptl_am_iface_tag_recv_cancel(uct_iface_h        iface,
                                              uct_tag_context_t *ctx,
                                              int                force);

void uct_ptl_am_iface_tag_recv_overflow(uct_iface_h tl_iface);

ucs_status_t uct_ptl_am_ep_atomic_cswap32(uct_ep_h tl_ep, uint32_t compare,
                                          uint32_t swap, uint64_t remote_addr,
                                          uct_rkey_t rkey, uint32_t *result,
                                          uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare,
                                          uint64_t swap, uint64_t remote_addr,
                                          uct_rkey_t rkey, uint64_t *result,
                                          uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_atomic32_post(uct_ep_h tl_ep, unsigned opcode,
                                         uint32_t value, uint64_t remote_addr,
                                         uct_rkey_t rkey);

ucs_status_t uct_ptl_am_ep_atomic64_post(uct_ep_h tl_ep, unsigned opcode,
                                         uint64_t value, uint64_t remote_addr,
                                         uct_rkey_t rkey);

ucs_status_t uct_ptl_am_ep_atomic32_fetch(uct_ep_h tl_ep, unsigned opcode,
                                          uint32_t value, uint32_t *result,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_atomic64_fetch(uct_ep_h        tl_ep,
                                          uct_atomic_op_t opcode,
                                          uint64_t value, uint64_t *result,
                                          uint64_t remote_addr, uct_rkey_t rkey,
                                          uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_flush(uct_ep_h tl_ep, unsigned flags,
                                 uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_fence(uct_ep_h tl_ep, unsigned flags);

void uct_ptl_am_ep_post_check(uct_ep_h tl_ep);

ucs_status_t uct_ptl_am_ep_get_address(uct_ep_h tl_ep, uct_ep_addr_t *addr);

int uct_ptl_am_ep_is_connected(const uct_ep_h                      tl_ep,
                               const uct_ep_is_connected_params_t *params);

ucs_status_t uct_ptl_am_ep_check(uct_ep_h tl_ep, unsigned flags,
                                 uct_completion_t *comp);

ucs_status_t uct_ptl_am_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *req,
                                       unsigned flags);

UCS_CLASS_DECLARE(uct_ptl_am_ep_t, const uct_ep_params_t *);
UCS_CLASS_DECLARE_NEW_FUNC(uct_ptl_am_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DECLARE_DELETE_FUNC(uct_ptl_am_ep_t, uct_ep_t);
#endif
