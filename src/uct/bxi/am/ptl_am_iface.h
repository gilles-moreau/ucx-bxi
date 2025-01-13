#ifndef PTL_AM_IFACE_H
#define PTL_AM_IFACE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <uct/bxi/base/ptl_iface.h>
#include <uct/bxi/base/ptl_rq.h>

#define UCT_PTL_RNDV_HW_MAGIC 0xDEAD
#define UCT_PTL_RNDV_SW_MAGIC 0xBEEF

#define UCT_PTL_HDR_RNDV_MATCH_MASK 0x0000000000ffffffULL
#define UCT_PTL_HDR_AM_ID_MASK      0x0000ffffff000000ULL
#define UCT_PTL_HDR_PROT_ID_MASK    0xffff000000000000ULL

#define UCT_PTL_HDR_GET_RNDV_MATCH(_hdr)                                       \
  ((uint32_t)(_hdr & UCT_PTL_HDR_RNDV_MATCH_MASK))
#define UCT_PTL_HDR_GET_AM_ID(_hdr)                                            \
  ((uint32_t)((_hdr & UCT_PTL_HDR_AM_ID_MASK) >> 24))
#define UCT_PTL_HDR_GET_PROT_ID(_hdr)                                          \
  ((uint32_t)((_hdr & UCT_PTL_HDR_PROT_ID_MASK) >> 48))

#define UCT_PTL_HDR_SET(_hdr, _rndv_match, _am_id, _prot_id)                   \
  _hdr  = ((_prot_id) & 0xffff);                                               \
  _hdr  = (_hdr << 24);                                                        \
  _hdr |= ((_am_id) & 0xffffff);                                               \
  _hdr  = (_hdr << 24);                                                        \
  _hdr |= ((_rndv_match) & 0xffffff);

#define UCT_PTL_IFACE_TM_IS_ENABLED(iface) (iface)->tm.enabled

#define UCT_PTL_IFACE_ACTIVATE(iface) (iface)->activated = 1

enum {
  UCT_PTL_AM_SHORT = 0,
  UCT_PTL_AM_BCOPY,
};

typedef struct uct_ptl_am_hdr_rndv {
  uint64_t remote_addr;
  size_t   length;
  size_t   header_length;
} uct_ptl_am_hdr_rndv_t;

typedef struct uct_ptl_am_iface_addr {
  ptl_pt_index_t am_pti;
  ptl_pt_index_t rma_pti;
  ptl_pt_index_t tag_pti;
} uct_ptl_am_iface_addr_t;

typedef struct uct_ptl_am_ep_addr {
  uct_ptl_ep_addr_t       super;
  uct_ptl_am_iface_addr_t iface_addr;
} uct_ptl_am_ep_addr_t;

typedef struct uct_ptl_am_iface_config {
  uct_ptl_iface_config_t super;
  int                    id;
  struct {
    int          enable;
    unsigned int list_size;
    unsigned int max_oop_ctx;
  } tm;
} uct_ptl_am_iface_config_t;

#define uct_ptl_am_tag_addr_hash(_ptr) kh_int64_hash_func((uintptr_t)(_ptr))
KHASH_INIT(uct_ptl_am_tag_addrs, void *, char, 0, uct_ptl_am_tag_addr_hash,
           kh_int64_hash_equal)

typedef struct uct_ptl_am_iface {
  uct_ptl_iface_t super;
  struct {
    int id;
  } config;
  struct {
    int                           enabled;
    unsigned int                  num_outstanding;
    unsigned int                  unexpected_cnt;
    unsigned int                  num_tags;
    khash_t(uct_ptl_am_tag_addrs) tag_addrs;
    ucs_queue_head_t              canceled_ops;
    unsigned int                  oop_ctx_cnt;
    uint32_t                      rndv_tag;
    struct {
      void                    *arg; /* User defined arg */
      uct_tag_unexp_eager_cb_t cb;  /* Callback for unexpected eager messages */
    } eager_unexp;
    struct {
      void                   *arg; /* User defined arg */
      uct_tag_unexp_rndv_cb_t cb;  /* Callback for unexpected rndv messages */
    } rndv_unexp;
  } tm;
  uct_ptl_mmd_t  am_mmd;
  uct_ptl_mmd_t *rma_mmd;
  uct_ptl_rq_t   am_rq;
  uct_ptl_rq_t   tag_rq;
  int            activated;
} uct_ptl_am_iface_t;

static inline int
uct_ptl_am_iface_cmp_iface_addr(uct_ptl_am_iface_addr_t *addr1,
                                uct_ptl_am_iface_addr_t *addr2)
{
  return addr1->am_pti == addr2->am_pti && addr1->rma_pti == addr2->rma_pti;
}

ucs_status_t uct_ptl_am_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                    uct_completion_t *comp);
ucs_status_t uct_ptl_am_iface_fence(uct_iface_h tl_iface, unsigned flags);

static UCS_F_ALWAYS_INLINE void
uct_ptl_am_iface_tag_del_from_hash(uct_ptl_am_iface_t *iface, void *buffer)
{
  khiter_t iter;

  iter = kh_get(uct_ptl_am_tag_addrs, &iface->tm.tag_addrs, buffer);
  ucs_assert(iter != kh_end(&iface->tm.tag_addrs));
  kh_del(uct_ptl_am_tag_addrs, &iface->tm.tag_addrs, iter);
}

#endif
