#ifndef BXI_CONN_H
#define BXI_CONN_H

#include "bxi.h"

#include <ucs/datastruct/frag_list.h>

/* Triplet to access a rendezvous counter. */
typedef struct uct_bxi_conn_id {
  ptl_process_t     pid;      /* Portals Process ID */
  ptl_pt_index_t    pti;      /* Portals Table Index */
  uct_ep_conn_key_t conn_key; /* Connection key */
} uct_bxi_conn_id_t;

/* Out-of-Order Object */
typedef struct uct_bxi_conn_ooo {
  ucs_frag_list_elem_t  elem;    /* Element in ooo connection list */
  uct_bxi_recv_block_t *block;   /* Receive block during ooo handling */
  uct_bxi_block_handler handler; /* Receive block handler */

  /* Cached event data */
  void            *start;
  ptl_size_t       mlength;
  ptl_size_t       rlength;
  ptl_match_bits_t match_bits;
  ptl_hdr_data_t   hdr_data;
  ptl_process_t    initiator;
  ptl_event_t     *ev;
} uct_bxi_conn_ooo_t;

typedef struct uct_bxi_conn {
  uct_bxi_conn_id_t id;     /* Counter connection ID */
  uint16_t          recv;   /* Counter of receive rndv requests */
  uint16_t          send;   /* Counter of send rndv requests */
  uint16_t          sn;     /* Message sequence number */
  ptl_pt_index_t    my_pti; /* PTI used during send. */
  ucs_frag_list_t   ooo_q;  /* Out of Order queue */
  ucs_mpool_t       ooo_mp; /* Memory pool of Out-of-order object */
} uct_bxi_conn_t;

ucs_status_t uct_bxi_conn_insert(uct_bxi_iface_t *iface, uct_bxi_conn_t *conn,
                                 uct_bxi_recv_block_t *block, ptl_event_t *ev,
                                 uct_bxi_block_handler handler, uint16_t sn);

uct_bxi_conn_t *uct_bxi_conn_get(uct_bxi_iface_t *iface, uct_bxi_conn_id_t id);

ucs_status_t uct_bxi_conn_create(uct_bxi_iface_t *iface, uct_bxi_conn_id_t id,
                                 uct_bxi_conn_t **conn_p);

#endif
