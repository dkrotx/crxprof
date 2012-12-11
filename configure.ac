AC_PREREQ([2.68])
AC_INIT([crxprof], [0.1], [https://github.com/dkrotx/crxprof/])

# This is where autoconf automatically generated files go
AC_CONFIG_AUX_DIR([config])
m4_include([m4/libunwind.m4])

AM_INIT_AUTOMAKE([1.10 no-define])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AM_PROG_CC_C_O

# Checks for libraries.
AC_CHECK_LIB([bfd], [bfd_openr], [], AC_MSG_ERROR([Could  not find bfd library]))
AC_CHECK_LIB([iberty], [cplus_demangle], [], AC_MSG_ERROR([Could  not find iberty library]))
AC_CHECK_LIB([rt], [clock_gettime], [], AC_MSG_ERROR([Could  not find rt library: system]))
AC_CHECK_LIB([z], [inflate], [], AC_MSG_ERROR([Could  not find z library: system]))

# Checks for header files.
AC_CHECK_HEADERS([fcntl.h inttypes.h stdint.h stdlib.h string.h sys/time.h unistd.h sys/ptrace.h demangle.h assert.h endian.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_TYPE_OFF_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT64_T

# Checks for library functions.
AC_HEADER_MAJOR
AC_FUNC_MALLOC
AC_CHECK_FUNCS([clock_getcpuclockid clock_gettime gettimeofday memchr memset strdup ptrace])


ACX_WITH_LIBUNWIND
ARCH_TAG=`uname -m`
AC_SUBST(ARCH_TAG)

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
