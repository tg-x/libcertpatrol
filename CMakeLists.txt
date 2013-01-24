cmake_minimum_required(VERSION 2.8)
project(certpatrol)
set(VERSION_MAJOR 0)
set(VERSION_MINOR 1)
set(VERSION_PATCH 0)
set(VERSION "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

if(NOT CMAKE_BUILD_TYPE)
  SET(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING
    "Choose the type of build, options are: None Debug Release RelWithDebInfo." FORCE)
endif()

set(CMAKE_C_FLAGS "-Wall" CACHE STRING
    "Common C flags" FORCE)
set(CMAKE_C_FLAGS_DEBUG "-ggdb -O0 -DDEBUG" CACHE STRING
    "C flags for debug build" FORCE)
set(CMAKE_C_FLAGS_RELWITHDEBINFO "-ggdb -O2" CACHE STRING
    "C flags for release with debug info" FORCE)
set(CMAKE_C_FLAGS_RELEASE "-O2" CACHE STRING
    "C flags for release" FORCE)

include(FindPkgConfig)
pkg_check_modules(PKG_GNUTLS gnutls REQUIRED)
pkg_check_modules(PKG_OPENSSL openssl)
pkg_check_modules(PKG_NSS nss)
pkg_check_modules(PKG_SQLITE sqlite3 REQUIRED)
pkg_check_modules(PKG_GTK gtk+-3.0 REQUIRED)
pkg_check_modules(PKG_GCR gcr-3 REQUIRED)

set(GNUTLS_INCLUDE_DIRS ${PKG_GNUTLS_INCLUDE_DIRS} CACHE STRING
    "GnuTLS include dirs")
set(GNUTLS_LIBDIR ${PKG_GNUTLS_LIBDIR} CACHE STRING
    "GnuTLS lib dir")
set(GNUTLS_LIBRARIES ${PKG_GNUTLS_LIBRARIES} CACHE STRING
    "GnuTLS libraries")

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

set(SQLITE_INCLUDE_DIRS ${PKG_SQLITE_INCLUDE_DIRS} CACHE STRING
    "SQLite include dirs")
set(SQLITE_LIBDIR ${PKG_SQLITE_LIBDIR} CACHE STRING
    "SQLite lib dir")
set(SQLITE_LIBRARIES ${PKG_SQLITE_LIBRARIES} CACHE STRING
    "SQLite libraries")

set(GTK_INCLUDE_DIRS ${PKG_GTK_INCLUDE_DIRS} CACHE STRING
    "GTK include dirs")
set(GTK_LIBDIR ${PKG_GTK_LIBDIR} CACHE STRING
    "GTK lib dir")
set(GTK_LIBRARIES ${PKG_GTK_LIBRARIES} CACHE STRING
    "GTK libraries")

set(GCR_INCLUDE_DIRS ${PKG_GCR_INCLUDE_DIRS} CACHE STRING
    "Gcr include dirs")
set(GCR_LIBDIR ${PKG_GCR_LIBDIR} CACHE STRING
    "Gcr lib dir")
set(GCR_LIBRARIES ${PKG_GCR_LIBRARIES} CACHE STRING
    "Gcr libraries")

include_directories(
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/include
    ${GNUTLS_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIRS}
    ${NSS_INCLUDE_DIRS}
    ${SQLITE_INCLUDE_DIRS}
    ${GTK_INCLUDE_DIRS}
    ${GCR_INCLUDE_DIRS}
)
link_directories(
    ${CMAKE_SOURCE_DIR}/lib
    ${GNUTLS_LDFLAGS}
    ${OPENSSL_LDFLAGS}
    ${NSS_LDFLAGS}
    ${SQLITE_LDFLAGS}
    ${GTK_LDFLAGS}
    ${GCR_LDFLAGS}
)

set(HAVE_GNUTLS ${GNUTLS_LIBRARIES})
set(HAVE_OPENSSL ${OPENSSL_LIBRARIES})
set(HAVE_NSS ${NSS_LIBRARIES})

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

if(${OS} MATCHES "^linux")
    set(LINUX 1)
elseif(${OS} MATCHES "darwin|rhapsody|macosx")
    set(OSX 1)
elseif(${OS} MATCHES "^freebsd")
    set(SOMEBSD 1)
    set(FREEBSD 1)
elseif(${OS} MATCHES "^openbsd")
    set(SOMEBSD 1)
    set(OPENBSD 1)
elseif(${OS} MATCHES "^netbsd")
    set(SOMEBSD 1)
    set(NETBSD 1)
elseif(${OS} MATCHES "solaris")
    set(SOLARIS 1)
    set(_REENTRANT 1)
elseif(${OS} MATCHES "arm-linux")
    set(LINUX 1)
elseif(${OS} MATCHES "cygwin")
    set(CYGWIN 1)
    set(WINDOWS 1)
elseif(${OS} MATCHES "mingw")
    set(MINGW 1)
    set(WINDOWS 1)
    set(_WIN32 1)
else()
    set(OTHEROS 1)
endif()

set(EXECUTABLE_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/bin")
set(LIBRARY_OUTPUT_PATH "${CMAKE_SOURCE_DIR}/lib")
set(CMAKE_BINARY_DIR .CMakeFiles)

configure_file(src/config.h.in src/config.h)

include(FindDoxygen)
add_custom_target(doc ${DOXYGEN_EXECUTABLE})
configure_file(Doxyfile.in Doxyfile @ONLY IMMEDIATE)

add_subdirectory(src)

file(GLOB_RECURSE headers RELATIVE ${CMAKE_SOURCE_DIR} "include/*.h")
foreach(h ${headers})
    GET_FILENAME_COMPONENT(f ${h} REALPATH)
    GET_FILENAME_COMPONENT(d ${h} PATH)
    install(FILES ${f} DESTINATION ${d})
endforeach()
