#### certpatrol ############################################

add_library(certpatrol SHARED
  certpatrol.c
  certpatrol-db-sqlite.c
)
target_link_libraries(certpatrol
    ${SQLITE_LIBRARIES}
)
install(TARGETS certpatrol DESTINATION lib)

#### certpatrol-gnutls #####################################

add_library(certpatrol-gnutls SHARED
  certpatrol-gnutls.c
)
target_link_libraries(certpatrol-gnutls
    certpatrol
    ${GNUTLS_LIBRARIES}
)
install(TARGETS certpatrol-gnutls DESTINATION lib)

#### certpatrol-openssl #####################################

if(OPENSSL_LIBRARIES)
    add_library(certpatrol-openssl SHARED
        certpatrol-openssl.c
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
        certpatrol-nss.c
    )
    target_link_libraries(certpatrol-nss
        certpatrol
        certpatrol-gnutls
        ${NSS_LIBRARIES}
    )
    install(TARGETS certpatrol-nss DESTINATION lib)
endif()

#### certpatrol-preload ####################################

set(SRC certpatrol-preload-gnutls.c)

if(OPENSSL_LIBRARIES)
   set (SRC ${SRC} certpatrol-preload-openssl.c)
endif()

if(NSS_LIBRARIES)
   set (SRC ${SRC} certpatrol-preload-nss.c)
endif()

add_library(certpatrol-preload SHARED ${SRC})
target_link_libraries(certpatrol-preload
    certpatrol
    certpatrol-gnutls
)
install(TARGETS certpatrol-preload DESTINATION lib)
