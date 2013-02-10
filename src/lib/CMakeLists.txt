#### certpatrol ############################################

set(SRC patrol.c patrol-db.c)
set(LIB certpatrol)

if (DB_BACKEND STREQUAL "dconf")
  set(SRC ${SRC} patrol-db-dconf.c)
  set(LIB ${LIB} ${DCONF_LIBRARIES} ${UUID_LIBRARIES})
elseif (DB_BACKEND STREQUAL "sqlite")
  set(SRC ${SRC} patrol-db-sqlite.c)
  set(LIB ${LIB} ${SQLITE_LIBRARIES} ${LIBTASN1_LIBRARIES})
endif ()

add_library(certpatrol SHARED ${SRC})
target_link_libraries(certpatrol ${LIB})
install(TARGETS certpatrol DESTINATION lib)

#### certpatrol-gnutls #####################################

add_library(certpatrol-gnutls SHARED
  patrol-gnutls.c
)
target_link_libraries(certpatrol-gnutls
    certpatrol
    ${GNUTLS_LIBRARIES}
    ${GNUTLS_DANE_LIBRARIES}
)
install(TARGETS certpatrol-gnutls DESTINATION lib)

#### certpatrol-openssl #####################################

if (OPENSSL_LIBRARIES)
    add_library(certpatrol-openssl SHARED
        patrol-openssl.c
    )
    target_link_libraries(certpatrol-openssl
        certpatrol
        certpatrol-gnutls
        ${OPENSSL_LIBRARIES}
    )
    install(TARGETS certpatrol-openssl DESTINATION lib)
endif ()

#### certpatrol-nss #####################################

if (NSS_LIBRARIES)
    add_library(certpatrol-nss SHARED
        patrol-nss.c
    )
    target_link_libraries(certpatrol-nss
        certpatrol
        certpatrol-gnutls
        ${NSS_LIBRARIES}
    )
    install(TARGETS certpatrol-nss DESTINATION lib)
endif ()

#### certpatrol-preload ####################################

set(SRC patrol-preload.c patrol-preload-gnutls.c)
set(LIB certpatrol certpatrol-gnutls)

if (OPENSSL_LIBRARIES)
   set(SRC ${SRC} patrol-preload-openssl.c)
   set(LIB ${LIB} certpatrol-openssl)
endif ()

if (NSS_LIBRARIES)
   set(SRC ${SRC} patrol-preload-nss.c)
   set(LIB ${LIB} certpatrol-nss)
endif ()

add_library(certpatrol-preload SHARED ${SRC})
target_link_libraries(certpatrol-preload ${LIB})
install(TARGETS certpatrol-preload DESTINATION lib)
