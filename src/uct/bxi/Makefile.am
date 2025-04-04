if HAVE_BXI

module_LTLIBRARIES = libuct_bxi.la
libuct_bxi_la_CPPFLAGS = $(BASE_CPPFLAGS) $(BXI_CPPFLAGS) 
libuct_bxi_la_CFLAGS = $(BASE_CFLAGS) $(LT_CFLAGS)
libuct_bxi_la_LIBADD = $(top_builddir)/src/ucs/libucs.la \
                       $(top_builddir)/src/uct/libuct.la \
											 $(BXI_LIBS)
libuct_bxi_la_LDFLAGS = $(BXI_LDFLAGS) -version-info $(SOVERSION)

noinst_HEADERS = \
								 bxi.h \
								 bxi_iface.h \
								 bxi_ep.h \
								 bxi_md.h \
								 bxi_rxq.h \
								 bxi_log.h 

libuct_bxi_la_SOURCES = \
												bxi_iface.c \
												bxi_ep.c \
												bxi_rxq.c \
												bxi_md.c

include $(top_srcdir)/config/module.am
# TODO: enable pkg-config processing when module static build is enabled
# include $(top_srcdir)/config/module-pkg-config.am

endif
