add_executable(http_server "main.cpp" "http_server.h" "http_server.cpp" "http_handle.h")
target_compile_definitions(http_server PUBLIC UNICODE _WIN32_WINNT=0x0600)
target_link_libraries(http_server PUBLIC Httpapi.lib windowsapp)
set_target_properties(http_server PROPERTIES CXX_STANDARD 17)