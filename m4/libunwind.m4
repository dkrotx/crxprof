AC_DEFUN([ACX_WITH_LIBUNWIND], [
  acx_with_libunwind=""
  AC_ARG_WITH([libunwind],
    [AS_HELP_STRING([--with-libunwind@<:@=Install DIR@:>@],
      [Specific path to libunwind installation])],
    [
        CPPFLAGS="$CPPFLAGS -I$with_libunwind/include"
        LIBS="$LIBS -L$with_libunwind/lib"
        acx_with_libunwind="$withval"
    ]
  )

  AC_LANG_SAVE
  AC_LANG_C
  AC_CHECK_HEADER([libunwind.h], [], [AC_MSG_ERROR([Unable to compile with the libunwind.])])
  AC_CHECK_LIB([unwind], [_U_dyn_register], [], [AC_MSG_ERROR(["Unable to link with libunwind])])
  AC_LANG_RESTORE
])
