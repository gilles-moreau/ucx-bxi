#include "bxihw_md.h"

#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <uct/base/uct_iface.h>

ucs_status_t uct_bxihw_md_open(uct_component_t *component, const char *md_name,
                               const uct_md_config_t *uct_md_config,
                               uct_md_h              *md_p)
{
  ucs_status_t           status;
  int                    fd, ver, ret;
  char                   path[PATH_MAX];
  struct bxi_init_arg    init;
  struct bxi_getinfo_arg getinfo;

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

err_close:
  close(fd);
err:
  return status;
}
