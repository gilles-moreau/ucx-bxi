#include "bxihw_md.h"

#include <ucs/arch/cpu.h>
#include <ucs/debug/memtrack_int.h>

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

ucs_status_t uct_bxihw_md_open(uct_component_t *component, const char *md_name,
                               const uct_md_config_t *uct_md_config,
                               uct_md_h              *md_p)
{
  ucs_status_t           status = UCS_OK;
  int                    fd, ver, ret;
  char                   path[PATH_MAX];
  uct_bxihw_md_t        *md;
  size_t                 offset;
  unsigned char         *txq_addr, *txq_head, *rxq_addr, *rxq_head;
  struct bxi_init_arg    init;
  struct bxi_getinfo_arg getinfo;
  uct_bxihw_shmem_t     *shmem;
  long                   page_size = sysconf(_SC_PAGESIZE);

  snprintf(path, PATH_MAX, "/dev/bxi/bxi0");
  fd = open(path, O_RDWR | O_CLOEXEC);
  if (fd < 0) {
    ucs_error("BXIHW: could not open device");
    status = UCS_ERR_IO_ERROR;
    goto err;
  }

  ver = ioctl(fd, BXI_IOC_GETVERSION);
  if (ver < 0) {
    ucs_error("BXIHW: get version");
    status = UCS_ERR_IO_ERROR;
    goto err_close;
  }

  if (ver >> 8 != BXI_IOCTL_VER_MAJOR || (ver & 0xff) < BXI_IOCTL_VER_MINOR) {
    ucs_error("BXIHW: version number");
    status = UCS_ERR_IO_ERROR;
    goto err_close;
  }

  init.pid     = -1;
  init.service = 0;
  init.group   = 1;
  init.maxpids = 1;
  ret          = ioctl(fd, BXI_IOC_INIT, (unsigned long)&init);
  if (ret < 0) {
    ucs_error("BXIHW: ioc init");
    status = UCS_ERR_IO_ERROR;
    goto err_close;
  }

  ret = ioctl(fd, BXI_IOC_GETINFO, (unsigned long)&getinfo);
  if (ret < 0) {
    ucs_error("BXIHW: ioc getinfo");
    status = UCS_ERR_IO_ERROR;
    goto err_close;
  }

  md = ucs_malloc(sizeof(uct_bxihw_md_t), "bxihw md");
  if (md == NULL) {
    status = UCS_ERR_NO_MEMORY;
    goto err_close;
  }

  md->nid          = getinfo.nid;
  md->pid          = getinfo.pid;
  md->uid          = geteuid();
  md->hwid         = getinfo.hwid;
  md->caps         = getinfo.capabilities;
  md->tx_cq_size   = getinfo.tx_cq_size;
  md->rx_cq_size   = getinfo.rx_cq_size;
  md->cq_head_size = getinfo.cq_head_size;

  ucs_info("BXIHW: caps. BXI_HW_CAP_EPU_CMD=%d",
           !!(md->caps & BXI_HW_CAP_EPU_CMD));
  ucs_info("BXIHW: caps. BXI_HW_CAP_FORCED_RELAXED_ORDERING=%d",
           !!(md->caps & BXI_HW_CAP_FORCED_RELAXED_ORDERING));

  /*
	 * map tx/rx queue
	 */
  offset = 0;

  txq_addr = mmap(NULL, md->tx_cq_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                  offset);
  if (txq_addr == MAP_FAILED) {
    ucs_error("BXIHW: couldn't mmap tx queue: %s\n", strerror(errno));
    goto err_free_md;
  }

  offset += getinfo.tx_cq_offset;

  rxq_addr = mmap(NULL, md->rx_cq_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
                  offset);
  if (rxq_addr == MAP_FAILED) {
    ucs_error("BXIHW: couldn't mmap rx queue: %s\n", strerror(errno));
    goto err_tx_addr;
  }

  offset += getinfo.rx_cq_offset;

  if (page_size != 65536) {
    txq_head = mmap(NULL, md->cq_head_size, PROT_READ, MAP_SHARED, fd, offset);
    if (txq_head == MAP_FAILED) {
      ucs_error("BXIHW: couldn't mmap tx head page: %s\n", strerror(errno));
      goto err_rx_addr;
    }

    offset += getinfo.cq_head_offset;

    rxq_head = mmap(NULL, md->cq_head_size, PROT_READ, MAP_SHARED, fd, offset);
    if (rxq_head == MAP_FAILED) {
      ucs_error("couldn't mmap rx head page: %s\n", strerror(errno));
      goto err_tx_head;
    }

    offset += getinfo.cq_head_offset;
  } else {
    txq_head = txq_addr + 0x8000;
    rxq_head = rxq_addr + 0x8000;
  }

  shmem = mmap(NULL, page_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, offset);
  if (shmem == MAP_FAILED) {
    ucs_error("BXIHW: couldn't mmap shmem page: %s\n", strerror(errno));
    goto err_rx_head;
  }
  md->shmem    = shmem;
  md->txq.lock = &md->shmem->tx_lock;
  md->rxq.lock = &md->shmem->rx_lock;

  md->txq.base    = txq_addr;
  md->txq.hw_head = txq_head;
  md->txq.head    = &md->shmem->tx_head;
  md->txq.tail    = &md->shmem->tx_tail;

  md->rxq.base    = rxq_addr;
  md->rxq.hw_head = rxq_head;
  md->rxq.head    = &md->shmem->rx_head;
  md->rxq.tail    = &md->shmem->rx_tail;

  /* Drain queues */
  while (((*md->txq.tail - *md->txq.head) & BXI_TX_PTRMASK) != 0)
    *md->txq.head = *md->txq.hw_head;
  while (((*md->rxq.tail - *md->rxq.head) & BXI_RX_PTRMASK) != 0)
    *md->rxq.head = *md->rxq.hw_head;

  if (ioctl(fd, BXI_IOC_CQENABLE) < 0) {
    ucs_error("BXIHW: BXI_IOC_CQENABLE: %s\n", strerror(errno));
    goto err_rx_head;
  }

  md->fd = fd;
  *md_p  = (uct_md_h)md;

  return status;

err_rx_head:
  munmap(rxq_head, md->cq_head_size);
err_tx_head:
  munmap(txq_head, md->cq_head_size);
err_rx_addr:
  munmap(rxq_addr, md->rx_cq_size);
err_tx_addr:
  munmap(txq_addr, md->tx_cq_size);
err_free_md:
  ucs_free(md);
err_close:
  close(fd);
err:
  return status;
}
