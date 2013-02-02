AC_PREREQ([2.59])
AC_INIT([crxprof], [0.1], [https://github.com/dkrotx/crxprof/])

# This is where autoconf automatically generated files go
AC_CONFIG_AUX_DIR([config])
m4_include([m4/libunwind.m4])

AM_INIT_AUTOMAKE([1.9.6 no-define])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.

dnl If CFLAGS isn't defined and using gcc, set CFLAGS to something reasonable.
dnl Otherwise, just prevent autoconf from molesting CFLAGS.
CFLAGS=$CFLAGS
AC_PROG_CC
if test "x$CFLAGS" = "x" ; then
    no_CFLAGS="yes"
fi

if test "x$no_CFLAGS" = "xyes" -a "x$GCC" = "xyes" ; then
    CFLAGS="-Wall -g -O2"
fi
dnl Append EXTRA_CFLAGS to CFLAGS, if defined.
if test "x$EXTRA_CFLAGS" != "x" ; then
    CFLAGS="$CFLAGS $EXTRA_CFLAGS"
fi

AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([z], [inflate], [], AC_MSG_ERROR([Could not find z library: libz-dev]))
AC_CHECK_LIB([iberty], [cplus_demangle], [], AC_MSG_ERROR([Could not find iberty library: binutils-dev]))
AC_CHECK_LIB([bfd], [bfd_openr], [], AC_MSG_ERROR([Could not find bfd library: binutils-dev]), [-liberty -lz])
AC_CHECK_LIB([rt], [clock_gettime], [], AC_MSG_ERROR([Could not find rt library: system]))

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h stdint.h stdlib.h string.h sys/time.h unistd.h sys/ptrace.h demangle.h assert.h endian.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AH_BOTTOM([#if HAVE_STDBOOL_H
#include <stdbool.h>
#else
#define bool char
#define false 0
#define true 1
#endif ])
AC_CHECK_TYPES([off_t, pid_t, size_t, ssize_t, uint64_t])

# Checks for library functions.
AC_HEADER_MAJOR
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_getcpuclockid clock_gettime gettimeofday memchr memset strdup ptrace])


ACX_WITH_LIBUNWIND
ARCH_TAG=`uname -m`
case $ARCH_TAG in
       @<:@iI@:>@?86) ARCH_TAG=x86 ;;
       @<:@xX@:>@86@<:@-_@:>@64) ARCH_TAG=x86_64 ;;
esac
AC_SUBST(ARCH_TAG)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
