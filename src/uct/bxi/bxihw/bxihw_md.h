#ifndef BXIHW_MD_H
#define BXIHW_MD_H

#include "bxihw.h"

#include <ucs/debug/log.h>
#include <uct/base/uct_md.h>

typedef struct uct_bxihw_shmem {
  unsigned int tx_lock;
  unsigned int rx_lock;
  unsigned int tx_tail;
  unsigned int rx_tail;
  unsigned int tx_head;
  unsigned int rx_head;
} uct_bxihw_shmem_t;

typedef struct uct_bxihw_cq {
  uint8_t               *base;
  volatile uint8_t      *hw_head;
  volatile unsigned int *tail;
  volatile unsigned int *head;
  volatile unsigned int *lock;
} uct_bxihw_cq_t;

typedef struct uct_bxihw_md {
  int                fd;
  int                pid, nid, hwid, uid;
  uct_bxihw_cq_t     txq, rxq;
  unsigned long      tx_cq_size;
  unsigned long      rx_cq_size;
  unsigned long      cq_head_size;
  uint64_t           caps;
  uct_bxihw_shmem_t *shmem;
} uct_bxihw_md_t;

ucs_status_t uct_bxihw_md_open(uct_component_t *component, const char *md_name,
                               const uct_md_config_t *uct_md_config,
                               uct_md_h              *md_p);

#endif
