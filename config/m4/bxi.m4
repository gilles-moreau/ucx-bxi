# BXI_BUILD_FLAGS(ARG, VAR_LIBS, VAR_LDFLAGS, VAR_CPPFLAGS)
# --------------------------------------------------------------------------
# Set up appropriate build flags for bxi
AC_DEFUN([BXI_BUILD_FLAGS], 
                $2="-lportals"
                $3="-L$1/lib -L$1/lib64"
                $4="-I$1/include"
        )

AC_DEFUN([BXIHW_BUILD_FLAGS], 
                $2="-I$1"
                $3="-I$1"
        )

AC_DEFUN([UCX_CHECK_BXIHW], [
                bxihw_happy="no"

                AC_ARG_WITH([bxihw],
                        [AS_HELP_STRING([--with-bxihw=(DIR)], [Enable the use 
                                of HW BXI (default is guess).])],
                        [], [with_bxihw=guess])

                AS_IF([test "x$with_bxihw" != xno],
                        [AS_IF([test "x$with_bxihw" = "xguess" -o "x$with_bxihw" = xyes -o "x$with_bxihw" = "x"],
                                [AC_MSG_NOTICE([BXI hardware path was not found, guessing ...])
                                 with_bxihw="/usr/include/"
                                 BXIHW_BUILD_FLAGS([$with_bxihw], [BXIHW_CFLAGS], [BXIHW_CPPFLAGS])],
                                [BXIHW_BUILD_FLAGS([$with_bxihw], [BXIHW_CFLAGS], [BXIHW_CPPFLAGS])])

                        save_CFLAGS="$CFLAGS"
                        save_CPPFLAGS="$CPPFLAGS"

                        CFLAGS="$BXIHW_CFLAGS $CFLAGS"
                        CPPFLAGS="$BXIHW_CPPFLAGS $CPPFLAGS"

                        AC_CHECK_HEADERS([linux/bxi/hw.h],
                                [bxihw_happy="yes"],
                                [bxihw_happy="no"])

                        AS_IF([test "x$bxihw_happy" = xyes],
                                [AC_DEFINE([HAVE_BXIHW], 1, [Enable BXIHW support])
                                 AC_SUBST([BXIHW_CFLAGS])
                                 AC_SUBST([BXIHW_CPPFLAGS])],
                                [AC_MSG_WARN([Hardware BXI not found])])

                       CPPFLAGS=$save_CPPFLAGS
                       CFLAGS=$save_CFLAGS],
                       [AC_MSG_WARN([HW BXI was explicitly disabled])]
                )

                AM_CONDITIONAL([HAVE_BXIHW], [test "x$bxihw_happy" != xno])

        ])

AC_DEFUN([UCX_CHECK_PTLBXI], [
                bxi_happy="no"

                AC_ARG_WITH([bxi],
                        [AS_HELP_STRING([--with-bxi=(DIR)], [Enable the use 
                                of BXI (default is guess).])],
                        [], [with_bxi=guess])

                AS_IF([test "x$with_bxi" != xno],
                        [AS_IF([test "x$with_bxi" = "xguess" -o "x$with_bxi" = xyes -o "x$with_bxi" = "x"],
                                [AC_MSG_NOTICE([Portals path was not found, guessing ...])
                                with_bxi="/opt/portals"
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

                        # First, check bxiv2
                        AS_IF([test "x$bxi_happy" = xyes],
                                        [AC_CHECK_LIB([portals], [PtlInit], 
                                                bxi_happy="yes"
						                                    BXI_LIBS="-lportals", 
                                                bxi_happy="no")])

                        # Then, check bxiv3
                        AS_IF([test "x$bxi_happy" = xno],
                              [LIBS="$save_LIBS -lportals-bxi3"
					                          AC_CHECK_LIB([portals-bxi3], [PtlInit], 
                                                  bxi_happy="yes"
						                                      BXI_LIBS="-lportals-bxi3", 
                                                  bxi_happy="no")])

 			                  AC_CHECK_DECLS([PTL_LE_MANAGE_LOCAL],
                                 			[AC_DEFINE([HAVE_BXI3_R6LITE], [1],
                                            		   [Check for BXI3 r6lite version])],
                                 			[],
                                 			[[#include <portals4.h>]])

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
