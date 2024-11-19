UCX_CHECK_BXI

AS_IF([test "x$bxi_happy" = xyes], [uct_modules="${uct_modules}:bxi"],[])
uct_bxi_modules=""
AC_DEFINE_UNQUOTED([uct_bxi_MODULES], ["${uct_bxi_modules}"], [BXI loadable modules])

AC_CONFIG_FILES([src/uct/bxi/Makefile])
