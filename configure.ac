AC_INIT(camxmctl,0.01)
AM_INIT_AUTOMAKE([subdir-objects foreign])
CXXFLAGS="$CXXFLAGS -std=c++17"
AC_PROG_CC
AC_PROG_CXX
AC_CONFIG_HEADERS([config.hpp])
AC_CONFIG_SRCDIR([src/camxmctl.cpp])
AC_CANONICAL_HOST
AC_CONFIG_MACRO_DIR([m4])

##############################################################################
###  Check pkg-config  - Required.  Needed to get lib paths/info
##############################################################################
AC_CHECK_PROG([PKGCONFIG],[pkg-config],[yes],[no])
AS_IF([test "${PKGCONFIG}" = "no" ],[
    AC_MSG_ERROR([Required package 'pkg-config' not found.])
  ]
)

##############################################################################
###  Check setting/getting thread names
##############################################################################
AC_CHECK_HEADERS(pthread_np.h,[PTHREAD_NP="yes"],[PTHREAD_NP="no"])

AC_MSG_CHECKING([for pthread_setname_np])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([#include <pthread.h>], [pthread_setname_np(pthread_self(), "name")])
  ],[
    AC_DEFINE([HAVE_PTHREAD_SETNAME_NP], [1], [Define if you have pthread_setname_np function.])
    PTHREAD_SETNAME_NP="yes"
    AC_MSG_RESULT([yes])
  ],[
    PTHREAD_SETNAME_NP="no"
    AC_MSG_RESULT([no])
  ]
)

AC_MSG_CHECKING([for pthread_getname_np])
AC_LINK_IFELSE(
  [AC_LANG_PROGRAM([#include <pthread.h>], [pthread_getname_np(pthread_self(), NULL, 0)])
  ],[
    AC_DEFINE([HAVE_PTHREAD_GETNAME_NP], [1], [Define if you have pthread_getname_np function.])
    PTHREAD_GETNAME_NP="yes"
    AC_MSG_RESULT([yes])
  ],[
    PTHREAD_GETNAME_NP="no"
    AC_MSG_RESULT([no])
  ]
)

##############################################################################
###  Check libmicrohttpd - Required.  Needed for stream/webcontrol
##############################################################################
AS_IF([pkgconf libmicrohttpd ], [
    TEMP_CPPFLAGS="$TEMP_CPPFLAGS "`pkgconf --cflags libmicrohttpd`
    TEMP_LIBS="$TEMP_LIBS "`pkgconf --libs libmicrohttpd`
  ],[
    AC_MSG_ERROR([Required package libmicrohttpd-dev not found, please check and install necessary dependencies])
  ]
)
HOLD_CPPFLAGS="$CPPFLAGS"
CPPFLAGS="$CPPFLAGS $TEMP_CPPFLAGS"
AC_CHECK_HEADERS(microhttpd.h,[MHTTP="yes"],[MHTTP="no"])
AC_MSG_CHECKING(libmicrohttpd libraries)
AC_MSG_RESULT($MHTTP)
AS_IF([test "${MHTTP}" != "yes" ], [
    AC_MSG_ERROR([Required package libmicrohttpd-dev not found, please check and install necessary dependencies])
  ]
)
CPPFLAGS="$HOLD_CPPFLAGS"

##############################################################################
###  Check pthread
##############################################################################
AC_CHECK_HEADERS(pthread.h,,AC_MSG_ERROR([pthread is required.]))
CPPFLAGS="${CPPFLAGS} -D_THREAD_SAFE "
LIBS="$LIBS -pthread "

TEMP_CPPFLAGS="$TEMP_CPPFLAGS -W -Wall -Werror -Wextra -Wformat -Wshadow -Wpointer-arith -Wwrite-strings -Winline -Wredundant-decls -Wno-long-long -ggdb -g3"

CPPFLAGS="$CPPFLAGS $TEMP_CPPFLAGS"
LIBS="$LIBS $TEMP_LIBS -lssl -lcrypto"
LDFLAGS="$TEMP_LDFLAGS"

AC_CONFIG_FILES([
	Makefile
	src/Makefile
	data/camxmctl-dist.conf
	data/sample-dist.html
])

AC_OUTPUT

##############################################################################
###  Report results to user
##############################################################################
echo ""
echo "   **************************"
echo "      Configure status       "
echo "      ${PACKAGE_NAME} ${PACKAGE_VERSION}"
echo "   **************************"
echo
echo "CFLAGS: $TEMP_CFLAGS $CFLAGS"
echo
echo "LIBS: $LIBS"
echo
echo "LDFLAGS: $TEMP_LDFLAGS $LDFLAGS"
echo
echo "OS                    : $host_os"
echo "pthread_np            : $PTHREAD_NP"
echo "pthread_setname_np    : $PTHREAD_SETNAME_NP"
echo "pthread_getname_np    : $PTHREAD_GETNAME_NP"
echo
echo  "Install prefix:       $prefix"
echo
