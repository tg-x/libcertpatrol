add_executable(certpatrol-dialog
  dialog.c
  dialog-window.c
)
add_dependencies(certpatrol-dialog certpatrol)
target_link_libraries(certpatrol-dialog
    certpatrol
    ${GCR_LIBRARIES}
)
install_targets(/bin certpatrol-dialog)
