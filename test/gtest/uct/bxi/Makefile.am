noinst_PROGRAMS = bxidp

bxidp_LDADD = \
	$(top_builddir)/src/ucs/libucs.la \
	$(top_builddir)/src/ucs/vfs/sock/libucs_vfs_sock.la \
	$(top_builddir)/src/uct/libuct.la \
	$(top_builddir)/src/ucm/libucm.la \
	$(top_builddir)/src/ucp/libucp.la \
	$(BXI_LIBS) \
	$(top_builddir)/src/uct/bxi/libuct_bxi.la \
	$(OPENMP_CFLAGS)

bxidp_SOURCES = \
  uct/bxi/bxidp.cc

bxidp_LDFLAGS = \
	$(BASE_CPPFLAGS) \
	-DTOP_SRCDIR=\"$(abs_top_srcdir)\" \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/test \
	-I$(top_builddir)/src \
	$(OPENMP_CFLAGS) \
	$(BXI_CPPFLAGS) \

bxidp_LDFLAGS += \
	$(BXIDP_CPPFLAGS)
	$(BXI_LDFLAGS)

bxidp_LDFLAGS += -Wl,--disable-new-dtags

bxidp_CFLAGS   = $(BASE_CFLAGS)

bxidp_CXXFLAGS = \
	$(BASE_CXXFLAGS) $(GTEST_CXXFLAGS) -std=c++11
