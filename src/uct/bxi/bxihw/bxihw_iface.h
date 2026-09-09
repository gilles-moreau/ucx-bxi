#ifndef BXIHW_IFACE_H
#define BXIHW_IFACE_H

#include "bxihw_md.h"

#include <uct/base/uct_iface.h>

typedef struct uct_bxihw_ev {
  ptl_addr_t        start;
  void             *user_ptr;
  ptl_hdr_data_t    hdr_data;
  ptl_match_bits_t  match_bits;
  ptl_size_t        rlength, mlength, remote_offset;
  ptl_uid_t         uid;
  union ptl_process initiator;
  ptl_event_kind_t  type;
  ptl_list_t        ptl_list;
  ptl_pt_index_t    pt_index;
  ptl_ni_fail_t     ni_fail_type;
  ptl_op_t          atomic_operation;
  ptl_datatype_t    atomic_type;
} uct_bxihw_ev_t;

typedef struct uct_bxihw_iface {
  uct_bxihw_md_t *dev;
  int             vni;

  struct {
    unsigned int nsr;
    unsigned int nmd;
    unsigned int neq;
    unsigned int nct;
    unsigned int ntrig;
    unsigned int nunex;
    unsigned int nme;
    unsigned int npte;
  } config;

  uint64_t        *sr;
  struct bxi_md   *md;
  struct bxi_eq   *eq;
  struct bxi_me   *me;
  struct bxi_me   *unex;
  struct bxi_pte  *pt;
  struct bxi_ct   *ct;
  struct bxi_trig *trig;

  void  *base;
  size_t base_size;

} uct_bxihw_iface_t;

ucs_status_t uct_bxihw_iface_init(uct_md_h md, uct_bxihw_iface_t **iface_p);

UCS_F_ALWAYS_INLINE unsigned int uct_bxihw_eq_order(unsigned int count)
{
  unsigned int ord;

  for (ord = BXI_MINORDER; ord <= BXI_EQINDEX_BITS; ord++) {
    if ((size_t)1 << ord > count)
      break;
  }
  if (ord > BXI_EQINDEX_BITS)
    return 0;
  return ord;
}

#endif
