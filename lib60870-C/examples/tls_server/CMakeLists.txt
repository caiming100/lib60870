include_directories(
   .
)

set(example_SRCS
   tls_server.c
)

IF(WIN32)
set_source_files_properties(${example_SRCS}
                                       PROPERTIES LANGUAGE CXX)
ENDIF(WIN32)

configure_file(server_CA1_1.key server_CA1_1.key COPYONLY)
configure_file(client_CA1_1.pem client_CA1_1.pem COPYONLY)
configure_file(root_CA1.pem root_CA1.pem COPYONLY)
configure_file(server_CA1_1.pem server_CA1_1.pem COPYONLY)

add_executable(tls_server
  ${example_SRCS}
)

target_link_libraries(tls_server
    lib60870
)
