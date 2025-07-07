#ifndef BXI_EP_H
#define BXI_EP_H

#include "bxi_iface.h"
#include "bxi_md.h"

#include <ucs/debug/debug_int.h>
#include <uct/api/uct.h>

enum {
  UCT_BXI_EP_CONN_CONNECTED     = UCS_BIT(0),
  UCT_BXI_EP_CONN_CLOSED        = UCS_BIT(1),
  UCT_BXI_EP_KEEP_ALIVE_PENDING = UCS_BIT(2),
  UCT_BXI_EP_FLUSH_REMOTE       = UCS_BIT(3),
};

typedef struct uct_bxi_ep_config {
  int max_retries;
} uct_bxi_ep_config_t;

typedef struct uct_bxi_ep {
  uct_base_ep_t         super;
  unsigned              flags;
  uct_bxi_device_addr_t dev_addr;
  uct_bxi_iface_addr_t  iface_addr;
  uint8_t               conn_state; /* Connection state. */
  uint16_t              list_id;    /* ID in Portals PID list. */
  ucs_list_link_t       elem;       /* Element in Portals PID list. */
  ucs_list_link_t       send_ops;   /* Queue of outstanding OPs */
} uct_bxi_ep_t;

typedef struct uct_bxi_ep_list {
  ucs_list_link_t head;
  unsigned        num_ep;
  ptl_process_t   pid;
} uct_bxi_ep_list_t;

static UCS_F_ALWAYS_INLINE void uct_bxi_ep_enable_flush(uct_bxi_ep_t *ep)
{
  ep->flags |= UCT_BXI_EP_FLUSH_REMOTE;
}

static UCS_F_ALWAYS_INLINE void uct_bxi_ep_disable_flush(uct_bxi_ep_t *ep)
{
  ep->flags = ~UCT_BXI_EP_FLUSH_REMOTE;
}

static UCS_F_ALWAYS_INLINE int uct_bxi_ep_is_intra_node(uct_bxi_ep_t *ep)
{
  uct_bxi_iface_t *iface =
          ucs_derived_of(ep->super.super.iface, uct_bxi_iface_t);
  return ep->dev_addr.pid.phys.nid == uct_bxi_iface_md(iface)->pid.phys.nid;
}

ucs_status_t uct_bxi_ep_put_short(uct_ep_h tl_ep, const void *buffer,
                                  unsigned length, uint64_t remote_addr,
                                  uct_rkey_t rkey);

ssize_t uct_bxi_ep_put_bcopy(uct_ep_h tl_ep, uct_pack_callback_t pack_cb,
                             void *arg, uint64_t remote_addr, uct_rkey_t rkey);

ucs_status_t uct_bxi_ep_put_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                  size_t iovcnt, uint64_t remote_addr,
                                  uct_rkey_t rkey, uct_completion_t *comp);

ucs_status_t uct_bxi_ep_get_bcopy(uct_ep_h              tl_ep,
                                  uct_unpack_callback_t unpack_cb, void *arg,
                                  size_t length, uint64_t remote_addr,
                                  uct_rkey_t rkey, uct_completion_t *comp);

ucs_status_t uct_bxi_ep_get_zcopy(uct_ep_h tl_ep, const uct_iov_t *iov,
                                  size_t iovcnt, uint64_t remote_addr,
                                  uct_rkey_t rkey, uct_completion_t *comp);

ucs_status_t uct_bxi_ep_am_short(uct_ep_h tl_ep, uint8_t id, uint64_t hdr,
                                 const void *buffer, unsigned length);

ucs_status_t uct_bxi_ep_am_short_iov(uct_ep_h ep, uint8_t id,
                                     const uct_iov_t *iov, size_t iovcnt);

ssize_t uct_bxi_ep_am_bcopy(uct_ep_h tl_ep, uint8_t id,
                            uct_pack_callback_t pack_cb, void *arg,
                            unsigned flags);

ucs_status_t uct_bxi_ep_am_zcopy(uct_ep_h tl_ep, uint8_t id, const void *header,
                                 unsigned header_length, const uct_iov_t *iov,
                                 size_t iovcnt, unsigned flags,
                                 uct_completion_t *comp);

ucs_status_t uct_bxi_ep_tag_eager_short(uct_ep_h ep, uct_tag_t tag,
                                        const void *data, size_t length);

ssize_t uct_bxi_ep_tag_eager_bcopy(uct_ep_h tl_ep, uct_tag_t tag, uint64_t imm,
                                   uct_pack_callback_t pack_cb, void *arg,
                                   unsigned flags);

ucs_status_t uct_bxi_ep_tag_eager_zcopy(uct_ep_h ep, uct_tag_t tag,
                                        uint64_t imm, const uct_iov_t *iov,
                                        size_t iovcnt, unsigned flags,
                                        uct_completion_t *comp);

ucs_status_ptr_t uct_bxi_ep_tag_rndv_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                           const void      *header,
                                           unsigned         header_length,
                                           const uct_iov_t *iov, size_t iovcnt,
                                           unsigned          flags,
                                           uct_completion_t *comp);

ucs_status_t uct_bxi_iface_tag_rndv_zcopy_get(uct_bxi_iface_t *iface,
                                              ptl_process_t    pid,
                                              ptl_pt_index_t   pti,
                                              uct_tag_t send_tag, void *buffer,
                                              size_t             length,
                                              uct_tag_context_t *ctx);

ucs_status_t uct_bxi_ep_tag_get_zcopy(uct_ep_h tl_ep, uct_tag_t tag,
                                      const uct_iov_t *iov, size_t iovcnt,
                                      uint64_t remote_offset, unsigned flags,
                                      uct_completion_t *comp);

ucs_status_t uct_bxi_ep_tag_rndv_cancel(uct_ep_h tl_ep, void *tl_op);

ucs_status_t uct_bxi_ep_tag_rndv_request(uct_ep_h ep, uct_tag_t tag,
                                         const void *header,
                                         unsigned    header_length,
                                         unsigned    flags);

ucs_status_t uct_bxi_iface_tag_gop_create(uct_iface_h tl_iface,
                                          uct_gop_h  *gop_p);

void uct_bxi_iface_tag_gop_delete(uct_iface_h tl_iface, uct_gop_h tl_gop);

ucs_status_t uct_bxi_iface_tag_gop_depends_on(uct_iface_h tl_iface,
                                              uct_gop_h   tl_gop,
                                              uct_gop_h  *tl_gops,
                                              size_t      gop_cnt);

ucs_status_t uct_bxi_iface_tag_recv_zcopy(uct_iface_h tl_iface, uct_tag_t tag,
                                          uct_tag_t        tag_mask,
                                          const uct_iov_t *iov, size_t iovcnt,
                                          uct_tag_context_t *ctx);

ucs_status_t uct_bxi_iface_tag_recv_cancel(uct_iface_h        iface,
                                           uct_tag_context_t *ctx, int force);

void uct_bxi_iface_tag_recv_overflow(uct_iface_h tl_iface);

ucs_status_t uct_bxi_ep_atomic_cswap32(uct_ep_h tl_ep, uint32_t compare,
                                       uint32_t swap, uint64_t remote_addr,
                                       uct_rkey_t rkey, uint32_t *result,
                                       uct_completion_t *comp);

ucs_status_t uct_bxi_ep_atomic_cswap64(uct_ep_h tl_ep, uint64_t compare,
                                       uint64_t swap, uint64_t remote_addr,
                                       uct_rkey_t rkey, uint64_t *result,
                                       uct_completion_t *comp);

ucs_status_t uct_bxi_ep_atomic32_post(uct_ep_h tl_ep, unsigned opcode,
                                      uint32_t value, uint64_t remote_addr,
                                      uct_rkey_t rkey);

ucs_status_t uct_bxi_ep_atomic64_post(uct_ep_h tl_ep, unsigned opcode,
                                      uint64_t value, uint64_t remote_addr,
                                      uct_rkey_t rkey);

ucs_status_t uct_bxi_ep_atomic32_fetch(uct_ep_h tl_ep, unsigned opcode,
                                       uint32_t value, uint32_t *result,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp);

ucs_status_t uct_bxi_ep_atomic64_fetch(uct_ep_h tl_ep, uct_atomic_op_t opcode,
                                       uint64_t value, uint64_t *result,
                                       uint64_t remote_addr, uct_rkey_t rkey,
                                       uct_completion_t *comp);

ucs_status_t uct_bxi_ep_flush(uct_ep_h tl_ep, unsigned flags,
                              uct_completion_t *comp);

ucs_status_t uct_bxi_ep_fence(uct_ep_h tl_ep, unsigned flags);

void uct_bxi_ep_post_check(uct_ep_h tl_ep);

ucs_status_t uct_bxi_ep_get_address(uct_ep_h tl_ep, uct_ep_addr_t *addr);

int uct_bxi_ep_is_connected(const uct_ep_h                      tl_ep,
                            const uct_ep_is_connected_params_t *params);

ucs_status_t uct_bxi_ep_check(uct_ep_h tl_ep, unsigned flags,
                              uct_completion_t *comp);

ucs_status_t uct_bxi_ep_pending_add(uct_ep_h tl_ep, uct_pending_req_t *req,
                                    unsigned flags);

ucs_status_t uct_bxi_ep_pending_get_add(uct_bxi_ep_t *ep, uct_tag_t tag,
                                        uct_bxi_recv_block_t *block);

void uct_bxi_ep_pending_purge_cb(uct_pending_req_t *self, void *arg);
void uct_bxi_ep_pending_purge(uct_ep_h tl_ep, uct_pending_purge_callback_t cb,
                              void *arg);

static UCS_F_ALWAYS_INLINE void
uct_bxi_ep_add_flush_op_sn(uct_bxi_ep_t *ep, uct_bxi_iface_send_op_t *op,
                           uint64_t sn)
{
  ucs_assert(op != NULL);
  ucs_assertv(!(op->flags & UCT_BXI_IFACE_SEND_OP_FLAG_INUSE), "op=%p", op);
  op->sn     = sn;
  op->flags |= UCT_BXI_IFACE_SEND_OP_FLAG_INUSE;

  //NOTE: Queue is used to complete flush operations.
  ucs_list_add_tail(&ep->send_ops, &op->elem);
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_ep_add_send_op(uct_bxi_ep_t *ep, uct_bxi_iface_send_op_t *op)
{
  uct_bxi_iface_t *iface =
          ucs_derived_of(ep->super.super.iface, uct_bxi_iface_t);

  ucs_assert(op != NULL);
  ucs_assertv(!(op->flags & UCT_BXI_IFACE_SEND_OP_FLAG_INUSE), "op=%p", op);
  op->flags |= UCT_BXI_IFACE_SEND_OP_FLAG_INUSE;

  //NOTE: Queue is used to complete flush operations.
  ucs_list_add_tail(&ep->send_ops, &op->elem);
  /* Remove one available send credit from iface. */
  uct_bxi_iface_available_add(iface, -1);
}

static UCS_F_ALWAYS_INLINE void
uct_bxi_ep_add_send_op_sn(uct_bxi_ep_t *ep, uct_bxi_iface_send_op_t *op,
                          uint64_t sn)
{
  op->sn = sn;
  uct_bxi_ep_add_send_op(ep, op);

  ucs_trace_poll("ep %p add send op %p sn %lu handler %s", ep, op, op->sn,
                 ucs_debug_get_symbol_name((void *)op->comp.handler));
}

UCS_CLASS_DECLARE(uct_bxi_ep_t, const uct_ep_params_t *);
UCS_CLASS_DECLARE_NEW_FUNC(uct_bxi_ep_t, uct_ep_t, const uct_ep_params_t *);
UCS_CLASS_DECLARE_DELETE_FUNC(uct_bxi_ep_t, uct_ep_t);

#endif
