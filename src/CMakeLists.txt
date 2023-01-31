add_executable(http_server "main.cpp")
target_compile_definitions(http_server PUBLIC UNICODE _WIN32_WINNT=0x0600)
target_link_libraries(http_server PUBLIC Httpapi.lib)