add_executable(certpatrol-dialog
  dialog.c
  dialog-window.c
)
add_dependencies(certpatrol-dialog certpatrol)

set(LIBS
    certpatrol
    ${GNUTLS_LIBRARIES}
    ${GTK_LIBRARIES}
    ${GCR_LIBRARIES}
)
if(GNUTLS_DANE_LIBRARIES)
    set(LIBS
        ${LIBS}
        ${GNUTLS_LIBRARIES}
        ${GNUTLS_DANE_LIBRARIES}
    )
endif()

target_link_libraries(certpatrol-dialog ${LIBS})
install_targets(/bin certpatrol-dialog)
