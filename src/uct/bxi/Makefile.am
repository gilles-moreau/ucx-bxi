if HAVE_BXI

module_LTLIBRARIES = libuct_bxi.la
libuct_bxi_la_CPPFLAGS = $(BASE_CPPFLAGS) $(BXI_CPPFLAGS) 
libuct_bxi_la_CFLAGS = $(BASE_CFLAGS) $(LT_CFLAGS)
libuct_bxi_la_LIBADD = $(top_builddir)/src/ucs/libucs.la \
                       $(top_builddir)/src/uct/libuct.la \
											 $(BXI_LIBS)
libuct_bxi_la_LDFLAGS = $(BXI_LDFLAGS) -version-info $(SOVERSION)

if HAVE_GDR_COPY
libuct_bxi_la_CPPFLAGS += $(GDR_COPY_CPPFLAGS)
libuct_bxi_la_LDFLAGS += $(GDR_COPY_LDFAGS) 
libuct_bxi_la_LIBADD += $(GDR_COPY_LIBS)
endif

noinst_HEADERS = \
								 bxi.h \
								 bxi_iface.h \
								 bxi_ep.h \
								 bxi_md.h \
								 bxi_rxq.h \
								 bxi_log.h 

libuct_bxi_la_SOURCES = \
												bxi_iface.c \
												bxi_iface_tag.c \
												bxi_ep.c \
												bxi_ep_tag.c \
												bxi_rxq.c \
												bxi_md.c

PKG_CONFIG_NAME=bxi

include $(top_srcdir)/config/module.am
# TODO: enable pkg-config processing when module static build is enabled
# include $(top_srcdir)/config/module-pkg-config.am

endif
