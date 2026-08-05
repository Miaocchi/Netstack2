# Compiler flags shared by the library and the test targets. Sources are
# listed explicitly (no glob): adding a file must be an intentional change.

set(TCPIP2_WARNINGS
    -Wall
    -Wextra
    -Wpedantic
    -Wshadow
    -Wconversion
    -Wno-sign-conversion
    -Werror=return-type
)

function(tcpip2_apply_common target)
    target_compile_features(${target} PRIVATE cxx_std_17)
    if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
        target_compile_options(${target} PRIVATE ${TCPIP2_WARNINGS})
    endif()
endfunction()
