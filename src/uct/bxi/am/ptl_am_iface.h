#ifndef PTL_AM_IFACE_H
#define PTL_AM_IFACE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <uct/bxi/base/ptl_iface.h>
#include <uct/bxi/base/ptl_rq.h>

#define UCT_PTL_RNDV_MAGIC 0xDEADBEAFUL

#define UCT_PTL_HDR_AM_ID_MASK 0x00000000ffffffffULL
#define UCT_PTL_HDR_PROT_ID_MASK 0xffffffff00000000ULL

#define UCT_PTL_HDR_GET_AM_ID(_hdr) ((uint32_t)(_hdr & UCT_PTL_HDR_AM_ID_MASK))
#define UCT_PTL_HDR_GET_PROT_ID(_hdr)                                          \
  ((uint32_t)((_hdr & UCT_PTL_HDR_PROT_ID_MASK) >> 32))

#define UCT_PTL_HDR_SET(_hdr, _am_id, _prot_id)                                \
  _hdr = ((_prot_id) & 0xffffffff);                                            \
  _hdr = (_hdr << 32);                                                         \
  _hdr |= ((_am_id) & 0xffffffff)

#define UCT_PTL_IFACE_TM_IS_ENABLED(iface) (iface)->tm.enabled

enum {
  UCT_PTL_AM_SHORT = 0,
  UCT_PTL_AM_BCOPY,
};

typedef struct uct_ptl_am_hdr_rndv {
  uint64_t remote_addr;
  size_t length;
} uct_ptl_am_hdr_rndv_t;

typedef struct uct_ptl_am_iface_addr {
  ptl_pt_index_t am_pti;
  ptl_pt_index_t rma_pti;
  ptl_pt_index_t tag_pti;
} uct_ptl_am_iface_addr_t;

typedef struct uct_ptl_am_ep_addr {
  uct_ptl_ep_addr_t super;
  uct_ptl_am_iface_addr_t iface_addr;
} uct_ptl_am_ep_addr_t;

typedef struct uct_ptl_am_iface_config {
  uct_ptl_iface_config_t super;
  int id;
  struct {
    int enable;
    unsigned int list_size;
  } tm;
} uct_ptl_am_iface_config_t;

typedef struct uct_ptl_am_iface {
  uct_ptl_iface_t super;
  struct {
    int id;
  } config;
  struct {
    int enabled;
    unsigned int num_outstanding;
    unsigned int unexpected_cnt;
    unsigned int num_tags;
    struct {
      void *arg;                   /* User defined arg */
      uct_tag_unexp_eager_cb_t cb; /* Callback for unexpected eager messages */
    } eager_unexp;
    struct {
      void *arg;                  /* User defined arg */
      uct_tag_unexp_rndv_cb_t cb; /* Callback for unexpected rndv messages */
    } rndv_unexp;
  } tm;
  uct_ptl_mmd_t am_mmd;
  uct_ptl_mmd_t *rma_mmd;
  uct_ptl_rq_t am_rq;
  uct_ptl_rq_t tag_rq;
} uct_ptl_am_iface_t;

static inline int
uct_ptl_am_iface_cmp_iface_addr(uct_ptl_am_iface_addr_t *addr1,
                                uct_ptl_am_iface_addr_t *addr2) {
  return addr1->am_pti == addr2->am_pti && addr1->rma_pti == addr2->rma_pti;
}

ucs_status_t uct_ptl_am_iface_flush(uct_iface_h tl_iface, unsigned flags,
                                    uct_completion_t *comp);
ucs_status_t uct_ptl_am_iface_fence(uct_iface_h tl_iface, unsigned flags);

#endif
