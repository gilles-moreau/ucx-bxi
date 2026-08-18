UCX_CHECK_BXIHW

AS_IF([test "x$bxihw_happy" = xyes], [uct_modules="${uct_modules}:bxihw"],[])
uct_bxihw_modules=""
AC_DEFINE_UNQUOTED([uct_bxihw_MODULES], ["${uct_bxihw_modules}"], [BXIHW loadable modules])

AC_CONFIG_FILES([src/uct/bxi/bxihw/Makefile
                 src/uct/bxi/bxihw/ucx-bxihw.pc])

UCX_CHECK_PTLBXI

AS_IF([test "x$bxi_happy" = xyes], [uct_modules="${uct_modules}:bxi"],[])
uct_bxi_modules=""
AC_DEFINE_UNQUOTED([uct_bxi_MODULES], ["${uct_bxi_modules}"], [BXI loadable modules])

AC_CONFIG_FILES([src/uct/bxi/Makefile
                 src/uct/bxi/ucx-bxi.pc])
