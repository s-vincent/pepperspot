#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ(2.57)
AC_INIT(pepperspot, 0.4, bugs@pepperspot.info)
AC_CONFIG_SRCDIR([src/cmdline.c])

AM_INIT_AUTOMAKE

AM_CONFIG_HEADER([config.h])

CFLAGS=""

# Checks for programs.
AC_PROG_CC

#JJAKO Check for libtool
# AC_PROG_LIBTOOL
# AM_PROG_LIBTOOL

# Checks for libraries.
# AC_CHECK_LIB(resolv, __res_close,,[echo -e "\tPlease install libresolv";exit])

# Checks for header files.
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h syslog.h unistd.h net/if_var.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_MODE_T
AC_TYPE_PID_T
AC_C_RESTRICT
AC_TYPE_SIZE_T
# AC_TYPE_SSIZE_T
AC_CHECK_MEMBERS([struct stat.st_rdev])
AC_HEADER_TIME
AC_STRUCT_TM
# AC_TYPE_UINT16_T
# AC_TYPE_UINT32_T
# AC_TYPE_UINT64_T
# AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
AC_FUNC_MALLOC
AC_FUNC_MEMCMP
AC_FUNC_MKTIME
AC_FUNC_REALLOC
AC_FUNC_SELECT_ARGTYPES
AC_CHECK_FUNCS([dup2 gethostbyname gettimeofday inet_ntoa memset select socket strchr strcspn strdup strerror strspn strstr strtol clearenv daemon tzset])

# Doxygen
DX_HTML_FEATURE(ON)
DX_CHM_FEATURE(OFF)
DX_CHI_FEATURE(OFF)
DX_MAN_FEATURE(ON)
DX_RTF_FEATURE(OFF)
DX_XML_FEATURE(OFF)
DX_PDF_FEATURE(OFF)
DX_PS_FEATURE(OFF)
DX_INIT_DOXYGEN(pepperspot, Doxyfile)

# Enable compilation in debug mode.
AC_ARG_ENABLE(debug-build, [  --enable-debug-build    allow to compile with debug informations [default=no]], enable_debug_build=$enableval, enable_debug_build=no)
if test "$enable_debug_build" = "yes"; then
  AC_DEFINE([DEBUG_BUILD], [1], [Enable debug build])
fi
AM_CONDITIONAL(ENABLE_DEBUG_BUILD, test "$enable_debug_build" = "yes")

AC_CONFIG_FILES([Makefile
                 doc/Makefile
                 man/Makefile
                 extra/Makefile
                 src/Makefile
                 debian/Makefile
                 contrib/Makefile
		 pepperspot.spec])
AC_OUTPUT

AC_MSG_NOTICE([Configuration

AC_PACKAGE_NAME version AC_PACKAGE_VERSION
  Enable debug build: .............. $enable_debug_build
])

