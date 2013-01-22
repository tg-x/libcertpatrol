#### certpatrol ############################################

add_library(certpatrol SHARED
  certpatrol.c
  certpatrol-db-sqlite.c
)
target_link_libraries(certpatrol
    -lsqlite3
)
install(TARGETS certpatrol DESTINATION lib)

#### certpatrol-gnutls #####################################

add_library(certpatrol-gnutls SHARED
  certpatrol-gnutls.c
)
add_dependencies(certpatrol-gnutls certpatrol)
target_link_libraries(certpatrol-gnutls
    -lcertpatrol
    ${GNUTLS_LIBRARIES}
)
install(TARGETS certpatrol-gnutls DESTINATION lib)

#### certpatrol-openssl #####################################

if(OPENSSL_LIBRARIES)
    add_library(certpatrol-openssl SHARED
        certpatrol-openssl.c
    )
    add_dependencies(certpatrol-openssl certpatrol-gnutls)
    target_link_libraries(certpatrol-openssl
        -lcertpatrol
        -lcertpatrol-gnutls
        ${OPENSSL_LIBRARIES}
    )
    install(TARGETS certpatrol-openssl DESTINATION lib)
endif()

#### certpatrol-nss #####################################

if(NSS_LIBRARIES)
    add_library(certpatrol-nss SHARED
        certpatrol-nss.c
    )
    add_dependencies(certpatrol-nss certpatrol-gnutls)
    target_link_libraries(certpatrol-nss
        -lcertpatrol
        -lcertpatrol-gnutls
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
add_dependencies(certpatrol-gnutls certpatrol)
target_link_libraries(certpatrol-gnutls
    -lcertpatrol
)
install(TARGETS certpatrol-preload DESTINATION lib)
