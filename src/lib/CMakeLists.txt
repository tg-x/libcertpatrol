#### certpatrol ############################################

add_library(certpatrol SHARED
  patrol.c
  patrol-db-sqlite.c
)
target_link_libraries(certpatrol
    ${SQLITE_LIBRARIES}
)
install(TARGETS certpatrol DESTINATION lib)

#### certpatrol-gnutls #####################################

add_library(certpatrol-gnutls SHARED
  patrol-gnutls.c
)
target_link_libraries(certpatrol-gnutls
    certpatrol
    ${GNUTLS_LIBRARIES}
)
install(TARGETS certpatrol-gnutls DESTINATION lib)

#### certpatrol-openssl #####################################

if(OPENSSL_LIBRARIES)
    add_library(certpatrol-openssl SHARED
        patrol-openssl.c
    )
    target_link_libraries(certpatrol-openssl
        certpatrol
        certpatrol-gnutls
        ${OPENSSL_LIBRARIES}
    )
    install(TARGETS certpatrol-openssl DESTINATION lib)
endif()

#### certpatrol-nss #####################################

if(NSS_LIBRARIES)
    add_library(certpatrol-nss SHARED
        patrol-nss.c
    )
    target_link_libraries(certpatrol-nss
        certpatrol
        certpatrol-gnutls
        ${NSS_LIBRARIES}
    )
    install(TARGETS certpatrol-nss DESTINATION lib)
endif()

#### certpatrol-preload ####################################

set(SRC patrol-preload-gnutls.c)

if(OPENSSL_LIBRARIES)
   set (SRC ${SRC} patrol-preload-openssl.c)
endif()

if(NSS_LIBRARIES)
   set (SRC ${SRC} patrol-preload-nss.c)
endif()

add_library(certpatrol-preload SHARED ${SRC})
target_link_libraries(certpatrol-preload
    certpatrol
    certpatrol-gnutls
)
install(TARGETS certpatrol-preload DESTINATION lib)
