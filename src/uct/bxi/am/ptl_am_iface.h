#ifndef PTL_AM_IFACE_H
#define PTL_AM_IFACE_H

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <uct/bxi/base/ptl_iface.h>
#include <uct/bxi/base/ptl_rq.h>

#define UCT_PTL_HDR_ID_MASK 0x00000000000000ffULL

#define UCT_PTL_HDR_GET_AM_ID(_hdr) ((uint8_t)(_hdr & UCT_PTL_HDR_ID_MASK))

#define UCT_PTL_HDR_SET(_hdr, _am_id) (_hdr = (_am_id & 0xff))

typedef struct uct_ptl_am_iface_addr {
  ptl_pt_index_t am_pti;
  ptl_pt_index_t rma_pti;
} uct_ptl_am_iface_addr_t;

typedef struct uct_ptl_am_iface_config {
  uct_ptl_iface_config_t super;
  int id;
} uct_ptl_am_iface_config_t;

typedef struct uct_ptl_am_iface {
  uct_ptl_iface_t super;
  struct {
    int id;
  } config;
  uct_ptl_mmd_t am_md;
  uct_ptl_mmd_t *rma_md;
  ucs_mpool_t am_mp;
  ucs_mpool_t rma_mp;
  uct_ptl_rq_t rq;
} uct_ptl_am_iface_t;

#endif
