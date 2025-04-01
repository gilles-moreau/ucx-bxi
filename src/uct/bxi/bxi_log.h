#ifndef UCT_BXI_LOG_H
#define UCT_BXI_LOG_H

#define uct_bxi_log_put(_iface)                                                \
  if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_DATA)) {                          \
    char buf[256] = {0};                                                       \
    uct_log_data(__FILE__, __LINE__, __func__, buf);                           \
  }

#define uct_bxi_log_recv_completion(_iface, _wc, _data, _length, _dump_cb,     \
                                    ...)                                       \
  if (ucs_log_is_enabled(UCS_LOG_LEVEL_TRACE_DATA)) {                          \
    char buf[256] = {0};                                                       \
    uct_log_data(__FILE__, __LINE__, __func__, buf);                           \
  }

#endif
