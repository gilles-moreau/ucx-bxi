if HAVE_BXIHW

module_LTLIBRARIES = libuct_bxihw.la
libuct_bxihw_la_CPPFLAGS = $(BASE_CPPFLAGS) $(BXIHW_CPPFLAGS) 
libuct_bxihw_la_CFLAGS = $(BASE_CFLAGS) $(LT_CFLAGS)
libuct_bxihw_la_LIBADD = $(top_builddir)/src/ucs/libucs.la \
                       $(top_builddir)/src/uct/libuct.la
libuct_bxihw_la_LDFLAGS = -version-info $(SOVERSION)

noinst_HEADERS = \
								 bxihw.h

libuct_bxihw_la_SOURCES = \
												bxihw_md.c

PKG_CONFIG_NAME=bxihw

include $(top_srcdir)/config/module.am
# TODO: enable pkg-config processing when module static build is enabled
# include $(top_srcdir)/config/module-pkg-config.am

endif
