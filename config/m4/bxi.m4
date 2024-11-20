# BXI_BUILD_FLAGS(ARG, VAR_LIBS, VAR_LDFLAGS, VAR_CPPFLAGS)
# --------------------------------------------------------------------------
# Set up appropriate build flags for bxi
AC_DEFUN([BXI_BUILD_FLAGS], 
                $2="-lportals"
                $3="-L$1/lib"
                $4="-I$1/include"
        )

AC_DEFUN([UCX_CHECK_BXI], [
                bxi_happy="no"

                AC_ARG_WITH([bxi],
                        [AS_HELP_STRING([--with-bxi=(DIR)], [Enable the use 
                                of BXI (default is guess).])],
                        [], [with_bxi=guess])

                AS_IF([test "x$with_bxi" != xno],
                        [AS_IF([test "x$with_bxi" = "xguess" -o "x$with_bxi" = xyes -o "x$with_bxi" = "x"],
                                [AC_MSG_NOTICE([Portals path was not found, guessing ...])
                                with_bxi="/opt/portals/"
                                BXI_BUILD_FLAGS([$with_bxi],
                                        [BXI_LIBS], [BXI_LDFLAGS], [BXI_CPPFLAGS])],
                                [BXI_BUILD_FLAGS([$with_bxi], 
                                        [BXI_LIBS], [BXI_LDFLAGS], [BXI_CPPFLAGS])]) 

                        save_CPPFLAGS="$CPPFLAGS"
                        save_LDFLAGS="$LFDLAGS"
                        save_LIBS="$LIBS"

                        CPPFLAGS="$BXI_CPPFLAGS $CPPFLAGS"
                        LDFLAGS="$BXI_LDFLAGS $LDFLAGS"
                        LIBS="$BXI_LIBS $LIBS"

                        AC_CHECK_HEADERS([portals4.h],
                                [bxi_happy="yes"],
                                [bxi_happy="no"])
                        AS_IF([test "x$bxi_happy" = xyes],
                                        [AC_CHECK_LIB([portals], [PtlInit], 
                                                bxi_happy="yes", 
                                                bxi_happy="no")])

                        AS_IF([test "x$bxi_happy" = xyes],
                                        [AC_DEFINE([HAVE_BXI], 1, [Enable BXI support])
                                        AC_SUBST([BXI_CPPFLAGS])
                                        AC_SUBST([BXI_LDFLAGS])
                                        AC_SUBST([BXI_LIBS])],
                                        [AC_MSG_WARN([Portals not found])])

                        CPPFLAGS=$save_CPPFLAGS
                        LDFLAGS=$save_LDFLAGS
                        LIBS=$save_LIBS],
                        [AC_MSG_WARN([BXI was explicitly disabled])]
        )

        AM_CONDITIONAL([HAVE_BXI], [test "x$bxi_happy" != xno])
        ])
