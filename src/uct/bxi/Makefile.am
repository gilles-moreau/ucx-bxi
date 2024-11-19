if HAVE_BXI

module_LTLIBRARIES = libuct_bxi.la
libuct_bxi_la_CPPFLAGS = $(BASE_CPPFLAGS) $(BXI_CPPFLAGS) 
libuct_bxi_la_CFLAGS = $(BASE_CFLAGS) $(LT_CFLAGS)
libuct_bxi_la_LIBADD = $(top_builddir)/src/ucs/libucs.la \
                       $(top_builddir)/src/uct/libuct.la
libuct_bxi_la_LDFLAGS = $(BXI_LDFLAGS) -version-info $(SOVERSION)

noinst_HEADERS = \
								 base/ptl_md.h 

libuct_bxi_la_SOURCES = \
												base/ptl_md.c

#noinst_HEADERS += \
#								 am/ptl_am_iface.h \
#								 am/ptl_am_ms.h \
#								 am/ptl_am_ep.h
#
## Active Message interface
#libuct_bxi_la_SOURCES += \
#												 am/ptl_am_iface.c \
#												 am/ptl_am_ms.c \
#												 am/ptl_am_ep.c
#
#
#noinst_HEADERS += \
#								 rma/ptl_rma_ms.h \
#								 rma/ptl_rma_iface.h \
#								 rma/ptl_rma_ep.h
#
## Remote Memory Address interface
#libuct_bxi_la_SOURCES += \
#												 rma/ptl_rma_iface.c \
#												 rma/ptl_rma_ms.c \
#												 rma/ptl_rma_ep.c
#
#noinst_HEADERS += \
#								 tag/ptl_tag_ms.h \
#								 tag/ptl_tag_iface.h \
#								 tag/ptl_tag_ep.h
#
## Remote Memory Address interface
#libuct_bxi_la_SOURCES += \
#												 tag/ptl_tag_iface.c \
#												 tag/ptl_tag_ms.c \
#												 tag/ptl_tag_ep.c

include $(top_srcdir)/config/module.am
# TODO: enable pkg-config processing when module static build is enabled
# include $(top_srcdir)/config/module-pkg-config.am

endif
