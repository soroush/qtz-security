# List of tests
set(QTZ_SECURITY_TESTS tst_encrypt tst_decrypt tst_sign tst_verify)
add_executable(tst_encrypt "tst_encrypt.cpp")
add_executable(tst_decrypt "tst_decrypt.cpp")
add_executable(tst_sign    "tst_sign.cpp")
add_executable(tst_verify  "tst_verify.cpp")

foreach(TEST_TARGET ${QTZ_SECURITY_TESTS})
    
    set_target_properties(${TEST_TARGET} PROPERTIES 
        DEBUG_POSTFIX "_d"
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED TRUE
    )

    target_include_directories(${TEST_TARGET}
        PRIVATE 
            $<BUILD_INTERFACE:${CMAKE_SOURCE_DIR}/lib/include>
            ${CMAKE_SOURCE_DIR}/lib/src
    )

    target_link_libraries(${TEST_TARGET} PRIVATE QtzSecurity)
endforeach()


add_custom_command (TARGET tst_encrypt POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory $<TARGET_FILE_DIR:QtzSecurity> $<TARGET_FILE_DIR:tst_encrypt>
)

# find Powershell and openssl executables
if(WIN32)
    find_program(POWERSHELL_PATH NAMES powershell)
elseif(UNIX)
    find_program(SH_PATH NAMES sh)
endif()

find_program(OPENSSL_PATH NAMES openssl)

# Add tests
if(WIN32)
    add_test(NAME "Generate" 
        COMMAND ${POWERSHELL_PATH} "-executionpolicy" "bypass" "-File" "${CMAKE_CURRENT_LIST_DIR}/generate-data.ps1" "-OpenSSL" ${OPENSSL_PATH} -WorkingDirectory ${CMAKE_CURRENT_BINARY_DIR}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
elseif(UNIX)
    add_test(NAME "Generate"
        COMMAND ${SH_PATH} "${CMAKE_CURRENT_LIST_DIR}/generate-data.sh" ${CMAKE_CURRENT_BINARY_DIR}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
    )
endif()

message(STATUS "SH_PATH is ${SH_PATH}")

add_test(NAME "Encrypt" COMMAND tst_encrypt ${CMAKE_CURRENT_BINARY_DIR} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties("Encrypt" PROPERTIES DEPENDS "Generate")

add_test(NAME "Decrypt" COMMAND tst_decrypt ${CMAKE_CURRENT_BINARY_DIR} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties("Decrypt" PROPERTIES DEPENDS "Generate")

add_test(NAME "Sign" COMMAND tst_sign ${CMAKE_CURRENT_BINARY_DIR} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties("Sign" PROPERTIES DEPENDS "Generate")

add_test(NAME "Verify" COMMAND tst_verify ${CMAKE_CURRENT_BINARY_DIR} WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})
set_tests_properties("Verify" PROPERTIES DEPENDS "Generate")
