cmake_minimum_required(VERSION 2.8)
project(certpatrol)
set(VERSION_MAJOR 0)
set(VERSION_MINOR 1)
set(VERSION_PATCH 0)
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

if (NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
      "Choose the type of build, options are: None Debug Release RelWithDebInfo." FORCE)
endif()

set(CMAKE_C_FLAGS "-Wall -std=gnu99" CACHE STRING
    "Common C flags" FORCE)
set(CMAKE_C_FLAGS_DEBUG "-g -ggdb -O0 -DDEBUG" CACHE STRING
    "C flags for debug build" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-g -ggdb -O2" CACHE STRING
    "C flags for release with debug info" FORCE)
set(CMAKE_C_FLAGS_RELEASE "-O2" CACHE STRING
    "C flags for release" FORCE)
set(DB_BACKEND "dconf" CACHE STRING
    "Database backend: auto / dconf / sqlite")

include(FindPkgConfig)

pkg_check_modules(PKG_GNUTLS gnutls REQUIRED)
pkg_check_modules(PKG_GNUTLS_DANE gnutls-dane)
pkg_check_modules(PKG_OPENSSL openssl)
pkg_check_modules(PKG_NSS nss)
pkg_check_modules(PKG_NSPR nspr)

pkg_check_modules(PKG_GCR gcr-3 REQUIRED)
pkg_check_modules(PKG_P11_KIT p11-kit-1 REQUIRED)

pkg_check_modules(PKG_GLIB glib-2.0 REQUIRED)
pkg_check_modules(PKG_ATK atk REQUIRED)
pkg_check_modules(PKG_GTK gtk+-3.0 REQUIRED)
pkg_check_modules(PKG_GDK_PIXBUF gdk-pixbuf-2.0 REQUIRED)
pkg_check_modules(PKG_CAIRO cairo REQUIRED)
pkg_check_modules(PKG_PANGO pango REQUIRED)
pkg_check_modules(PKG_PANGOCAIRO pangocairo REQUIRED)

pkg_check_modules(PKG_DCONF dconf)
pkg_check_modules(PKG_UUID uuid)

pkg_check_modules(PKG_SQLITE sqlite3)
pkg_check_modules(PKG_LIBTASN1 libtasn1)

set(DCONF_INCLUDE_DIRS ${PKG_DCONF_INCLUDE_DIRS} CACHE STRING
    "dconf include dirs")
set(DCONF_LIBDIR ${PKG_DCONF_LIBDIR} CACHE STRING
    "dconf lib dir")
set(DCONF_LIBRARIES ${PKG_DCONF_LIBRARIES} CACHE STRING
    "dconf libraries")

set(UUID_INCLUDE_DIRS ${PKG_UUID_INCLUDE_DIRS} CACHE STRING
    "uuid include dirs")
set(UUID_LIBDIR ${PKG_UUID_LIBDIR} CACHE STRING
    "uuid lib dir")
set(UUID_LIBRARIES ${PKG_UUID_LIBRARIES} CACHE STRING
    "uuid libraries")

set(SQLITE_INCLUDE_DIRS ${PKG_SQLITE_INCLUDE_DIRS} CACHE STRING
    "SQLite include dirs")
set(SQLITE_LIBDIR ${PKG_SQLITE_LIBDIR} CACHE STRING
    "SQLite lib dir")
set(SQLITE_LIBRARIES ${PKG_SQLITE_LIBRARIES} CACHE STRING
    "SQLite libraries")

set(LIBTASN1_INCLUDE_DIRS ${PKG_LIBTASN1_INCLUDE_DIRS} CACHE STRING
    "libtasn1 include dirs")
set(LIBTASN1_LIBDIR ${PKG_LIBTASN1_LIBDIR} CACHE STRING
    "libtasn1 lib dir")
set(LIBTASN1_LIBRARIES ${PKG_LIBTASN1_LIBRARIES} CACHE STRING
    "libtasn1 libraries")

set(GNUTLS_INCLUDE_DIRS ${PKG_GNUTLS_INCLUDE_DIRS} CACHE STRING
    "GnuTLS include dirs")
set(GNUTLS_LIBDIR ${PKG_GNUTLS_LIBDIR} CACHE STRING
    "GnuTLS lib dir")
set(GNUTLS_LIBRARIES ${PKG_GNUTLS_LIBRARIES} CACHE STRING
    "GnuTLS libraries")

set(GNUTLS_DANE_INCLUDE_DIRS ${PKG_GNUTLS_DANE_INCLUDE_DIRS} CACHE STRING
    "GnuTLS DANE include dirs")
set(GNUTLS_DANE_LIBDIR ${PKG_GNUTLS_DANE_LIBDIR} CACHE STRING
    "GnuTLS DANE lib dir")
set(GNUTLS_DANE_LIBRARIES ${PKG_GNUTLS_DANE_LIBRARIES} CACHE STRING
    "GnuTLS DANE libraries")

set(OPENSSL_INCLUDE_DIRS ${PKG_OPENSSL_INCLUDE_DIRS} CACHE STRING
    "OpenSSL include dirs")
set(OPENSSL_LIBDIR ${PKG_OPENSSL_LIBDIR} CACHE STRING
    "OpenSSL lib dir")
set(OPENSSL_LIBRARIES ${PKG_OPENSSL_LIBRARIES} CACHE STRING
    "OpenSSL libraries")

set(NSS_INCLUDE_DIRS ${PKG_NSS_INCLUDE_DIRS} CACHE STRING
    "NSS include dirs")
set(NSS_LIBDIR ${PKG_NSS_LIBDIR} CACHE STRING
    "NSS lib dir")
set(NSS_LIBRARIES ${PKG_NSS_LIBRARIES} CACHE STRING
    "NSS libraries")

set(NSPR_INCLUDE_DIRS ${PKG_NSPR_INCLUDE_DIRS} CACHE STRING
    "NSPR include dirs")
set(NSPR_LIBDIR ${PKG_NSPR_LIBDIR} CACHE STRING
    "NSPR lib dir")
set(NSPR_LIBRARIES ${PKG_NSPR_LIBRARIES} CACHE STRING
    "NSPR libraries")

set(GCR_INCLUDE_DIRS ${PKG_GCR_INCLUDE_DIRS} CACHE STRING
    "Gcr include dirs")
set(GCR_LIBDIR ${PKG_GCR_LIBDIR} CACHE STRING
    "Gcr lib dir")
set(GCR_LIBRARIES ${PKG_GCR_LIBRARIES} CACHE STRING
    "Gcr libraries")

set(P11_KIT_INCLUDE_DIRS ${PKG_P11_KIT_INCLUDE_DIRS} CACHE STRING
    "p11-kit include dirs")
set(P11_KIT_LIBDIR ${PKG_P11_KIT_LIBDIR} CACHE STRING
    "p11-kit lib dir")
set(P11_KIT_LIBRARIES ${PKG_P11_KIT_LIBRARIES} CACHE STRING
    "p11-kit libraries")

set(GLIB_INCLUDE_DIRS ${PKG_GLIB_INCLUDE_DIRS} CACHE STRING
    "glib include dirs")
set(GLIB_LIBDIR ${PKG_GLIB_LIBDIR} CACHE STRING
    "glib lib dir")
set(GLIB_LIBRARIES ${PKG_GLIB_LIBRARIES} CACHE STRING
    "glib libraries")

set(ATK_INCLUDE_DIRS ${PKG_ATK_INCLUDE_DIRS} CACHE STRING
    "ATK include dirs")
set(ATK_LIBDIR ${PKG_ATK_LIBDIR} CACHE STRING
    "ATK lib dir")
set(ATK_LIBRARIES ${PKG_ATK_LIBRARIES} CACHE STRING
    "ATK libraries")

set(GTK_INCLUDE_DIRS ${PKG_GTK_INCLUDE_DIRS} CACHE STRING
    "GTK include dirs")
set(GTK_LIBDIR ${PKG_GTK_LIBDIR} CACHE STRING
    "GTK lib dir")
set(GTK_LIBRARIES ${PKG_GTK_LIBRARIES} CACHE STRING
    "GTK libraries")

set(GDK_PIXBUF_INCLUDE_DIRS ${PKG_GTK_INCLUDE_DIRS} CACHE STRING
    "GDK-Pixbuf include dirs")
set(GDK_PIXBUF_LIBDIR ${PKG_GDK_PIXBUF_LIBDIR} CACHE STRING
    "GDK-Pixbuf lib dir")
set(GDK_PIXBUF_LIBRARIES ${PKG_GDK_PIXBUF_LIBRARIES} CACHE STRING
    "GDK-Pixbuf libraries")

set(CAIRO_INCLUDE_DIRS ${PKG_CAIRO_INCLUDE_DIRS} CACHE STRING
    "Cairo include dirs")
set(CAIRO_LIBDIR ${PKG_CAIRO_LIBDIR} CACHE STRING
    "Cairo lib dir")
set(CAIRO_LIBRARIES ${PKG_CAIRO_LIBRARIES} CACHE STRING
    "Cairo libraries")

set(PANGO_INCLUDE_DIRS ${PKG_PANGO_INCLUDE_DIRS} CACHE STRING
    "Pango include dirs")
set(PANGO_LIBDIR ${PKG_PANGO_LIBDIR} CACHE STRING
    "Pango lib dir")
set(PANGO_LIBRARIES ${PKG_PANGO_LIBRARIES} CACHE STRING
    "Pango libraries")

set(PANGOCAIRO_INCLUDE_DIRS ${PKG_PANGOCAIRO_INCLUDE_DIRS} CACHE STRING
    "Pango Cairo include dirs")
set(PANGOCAIRO_LIBDIR ${PKG_PANGOCAIRO_LIBDIR} CACHE STRING
    "Pango Cairo lib dir")
set(PANGOCAIRO_LIBRARIES ${PKG_PANGOCAIRO_LIBRARIES} CACHE STRING
    "Pango Cairo libraries")

if (DB_BACKEND STREQUAL "auto")
  if (DCONF_LIBRARIES AND UUID_LIBRARIES)
    set(DB_BACKEND "dconf")

  elseif (SQLITE_LIBRARIES AND LIBTASN1_LIBRARIES)
    set(DB_BACKEND "sqlite")

  else ()
    message(FATAL_ERROR "Missing libraries:\n"
      "Either dconf and uuid, or sqlite and libtasn1 is required.")
  endif ()
endif ()

if (DB_BACKEND STREQUAL "dconf")
  if (NOT DCONF_LIBRARIES)
    message(FATAL_ERROR "Missing library: dconf is required.\n")
  endif ()

  if (NOT UUID_LIBRARIES)
    message(FATAL_ERROR "Missing library: uuid is required.\n")
  endif ()

  set(SQLITE_LIBRARIES "")
  set(LIBTASN1_LIBRARIES "")

elseif (DB_BACKEND STREQUAL "sqlite")
  if (NOT SQLITE_LIBRARIES)
    message(FATAL_ERROR "Missing library: sqlite is required.\n")
  endif ()

  if (NOT LIBTASN1_LIBRARIES)
    message(FATAL_ERROR "Missing library: libtasn1 is required.\n")
  endif ()

  set(DCONF_LIBRARIES "")
  set(UUID_LIBRARIES "")
endif ()

include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include

    ${GNUTLS_INCLUDE_DIRS}
    ${GNUTLS_DANE_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${NSS_INCLUDE_DIRS}
    ${NSPR_INCLUDE_DIRS}

    ${DCONF_INCLUDE_DIRS}
    ${UUID_INCLUDE_DIRS}

    ${SQLITE_INCLUDE_DIRS}
    ${LIBTASN1_INCLUDE_DIRS}

    ${GCR_INCLUDE_DIRS}
    ${P11_KIT_INCLUDE_DIRS}

    ${GLIB_INCLUDE_DIRS}
    ${ATK_INCLUDE_DIRS}
    ${GTK_INCLUDE_DIRS}
    ${GDK_PIXBUF_INCLUDE_DIRS}
    ${CAIRO_INCLUDE_DIRS}
    ${PANGO_INCLUDE_DIRS}
    ${PANGOCAIRO_INCLUDE_DIRS}
)
link_directories(
    ${CMAKE_SOURCE_DIR}/lib

    ${GNUTLS_LIBDIR}
    ${GNUTLS_DANE_LIBDIR}
    ${OPENSSL_LIBDIR}
    ${NSS_LIBDIR}
    ${NSPR_LIBDIR}

    ${DCONF_LIBDIR}
    ${UUID_LIBDIR}

    ${SQLITE_LIBDIR}
    ${LIBASN1_LIBDIR}

    ${GCR_LIBDIR}
    ${P11_KIT_LIBDIR}

    ${GLIB_LIBDIR}
    ${ATK_LIBDIR}
    ${GTK_LIBDIR}
    ${GDK_PIXBUF_LIBDIR}
    ${CAIRO_LIBDIR}
    ${PANGO_LIBDIR}
    ${PANGOCAIRO_LIBDIR}
)

set(HAVE_GNUTLS ${GNUTLS_LIBRARIES})
set(HAVE_GNUTLS_DANE ${GNUTLS_DANE_LIBRARIES})
set(HAVE_OPENSSL ${OPENSSL_LIBRARIES})
if (NSS_LIBRARIES AND NSPR_LIBRARIES)
  set(HAVE_NSS 1)
endif ()

include(CheckIncludeFile)

check_include_file("argz.h" HAVE_ARGZ_H)
check_include_file("dlfcn.h" HAVE_DLFCN_H)
check_include_file("errno.h" HAVE_ERRNO_H)
check_include_file("inttypes.h" HAVE_INTTYPES_H)
check_include_file("langinfo.h" HAVE_LANGINFO_H)
check_include_file("libintl.h" HAVE_LIBINTL_H)
check_include_file("locale.h" HAVE_LOCALE_H)
check_include_file("memory.h" HAVE_MEMORY_H)
check_include_file("netinet/in.h" HAVE_NETINET_IN_H)
check_include_file("stdarg.h" HAVE_STDARG_H)
check_include_file("stddef.h" HAVE_STDDEF_H)
check_include_file("stdint.h" HAVE_STDINT_H)
check_include_file("stdio.h" HAVE_STDIO_H)
check_include_file("stdlib.h" HAVE_STDLIB_H)
check_include_file("strings.h" HAVE_STRINGS_H)
check_include_file("string.h" HAVE_STRING_H)
check_include_file("sys/socket.h" HAVE_SYS_SOCKET_H)
check_include_file("sys/stat.h" HAVE_SYS_STAT_H)
check_include_file("sys/types.h" HAVE_SYS_TYPES_H)
check_include_file("unistd.h" HAVE_UNISTD_H)

string(TOLOWER ${CMAKE_SYSTEM_NAME} OS)

if (${OS} MATCHES "^linux")
    set(LINUX 1)
elseif (${OS} MATCHES "darwin|rhapsody|macosx")
    set(OSX 1)
elseif (${OS} MATCHES "^freebsd")
    set(SOMEBSD 1)
    set(FREEBSD 1)
elseif (${OS} MATCHES "^openbsd")
    set(SOMEBSD 1)
    set(OPENBSD 1)
elseif (${OS} MATCHES "^netbsd")
    set(SOMEBSD 1)
    set(NETBSD 1)
elseif (${OS} MATCHES "solaris")
    set(SOLARIS 1)
    set(_REENTRANT 1)
elseif (${OS} MATCHES "arm-linux")
    set(LINUX 1)
elseif(${OS} MATCHES "cygwin")
    set(CYGWIN 1)
    set(WINDOWS 1)
elseif (${OS} MATCHES "mingw")
    set(MINGW 1)
    set(WINDOWS 1)
    set(_WIN32 1)
else ()
    set(OTHEROS 1)
endif ()

set(EXECUTABLE_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/bin")
set(LIBRARY_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/lib")
set(CMAKE_BINARY_DIR .CMakeFiles)

configure_file(src/config.h.in src/config.h)

include(FindDoxygen)
add_custom_target(doc ${DOXYGEN_EXECUTABLE})
configure_file(Doxyfile.in Doxyfile @ONLY IMMEDIATE)

add_subdirectory(src)

file(GLOB_RECURSE paths RELATIVE ${CMAKE_SOURCE_DIR} "include/*.h")
foreach(p ${paths})
    get_filename_component(f ${p} REALPATH)
    get_filename_component(d ${p} PATH)
#    install(FILES ${f} DESTINATION ${d})
endforeach()

file(GLOB_RECURSE paths RELATIVE ${CMAKE_SOURCE_DIR} "etc/*")
foreach(p ${paths})
    get_filename_component(f ${p} REALPATH)
    get_filename_component(d ${p} PATH)
    if (CMAKE_INSTALL_PREFIX MATCHES "^/usr/?$")
      set(d "/${d}")
    endif()
    install(FILES ${f} DESTINATION ${d})
endforeach()
