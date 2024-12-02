#ifndef PTL_AM_IFACE_H
#define PTL_AM_IFACE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <uct/bxi/base/ptl_iface.h>
#include <uct/bxi/base/ptl_rq.h>

#define UCT_PTL_HDR_AM_ID_MASK 0x00000000000000ffULL
#define UCT_PTL_HDR_PROT_ID_MASK 0x000000000000ff00ULL

#define UCT_PTL_HDR_GET_AM_ID(_hdr) ((uint8_t)(_hdr & UCT_PTL_HDR_AM_ID_MASK))
#define UCT_PTL_HDR_GET_PROT_ID(_hdr)                                          \
  ((uint8_t)((_hdr & UCT_PTL_HDR_PROT_ID_MASK) >> 8))

#define UCT_PTL_HDR_SET(_hdr, _am_id, _prot_id)                                \
  _hdr = ((_prot_id) & 0xff);                                                  \
  _hdr = (_hdr << 8);                                                          \
  _hdr |= ((_am_id) & 0xff)

enum {
  UCT_PTL_AM_SHORT = 0,
  UCT_PTL_AM_BCOPY,
};

typedef struct uct_ptl_am_iface_addr {
  ptl_pt_index_t am_pti;
  ptl_pt_index_t rma_pti;
} uct_ptl_am_iface_addr_t;

typedef struct uct_ptl_am_ep_addr {
  uct_ptl_ep_addr_t super;
  uct_ptl_am_iface_addr_t iface_addr;
} uct_ptl_am_ep_addr_t;

typedef struct uct_ptl_am_iface_config {
  uct_ptl_iface_config_t super;
  int id;
} uct_ptl_am_iface_config_t;

typedef struct uct_ptl_am_iface {
  uct_ptl_iface_t super;
  struct {
    int id;
  } config;
  uct_ptl_mmd_t am_mmd;
  uct_ptl_mmd_t *rma_mmd;
  ucs_mpool_t short_mp;
  uct_ptl_rq_t rq;
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
