cmake_minimum_required(VERSION 3.10)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Check for dependencies
find_package(Qt5 COMPONENTS Core REQUIRED)
find_package(OpenSSL REQUIRED)

# OS-dependent sources
set(OS_SOURCES )
if(WIN32)
    list(APPEND OS_SOURCES ${PROJECT_NAME}.rc)
endif()

# Define the library
add_library (${PROJECT_NAME} SHARED
    # src/virtual-machine-detector.cpp
    src/username.cpp
    src/unique-machine-id.cpp
    src/token.cpp
    src/password.cpp
    src/license-manager.cpp
    src/key-ring.cpp
    src/identity.cpp
    src/crypto.cpp
    src/authorizer.cpp
    src/authenticator.cpp
    src/authentication-source.cpp
    # Headers
    # include/virtual-machine-detector.hpp
    include/username.hpp
    include/unique-machine-id.hpp
    include/token.hpp
    include/qtz-security.hpp
    include/password.hpp
    include/license-manager.hpp
    include/key-ring.hpp
    include/identity.hpp
    include/crypto.hpp
    include/authorizer.hpp
    include/authenticator.hpp
    include/authentication-source.hpp
    ${OS_SOURCES}
)

target_include_directories(${PROJECT_NAME}
    PUBLIC 
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}> 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Set properties
set_target_properties(QtzSecurity PROPERTIES 
    VERSION 0.4.0
    SOVERSION 0
    DEBUG_POSTFIX d
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED TRUE
    DEFINE_SYMBOL QTZ_SECURITY_LIBRARY
    PUBLIC_HEADER "include/qtz-security.hpp"
)

# Copy headers for local builds
if(QTZ_LOCAL_BUILD)
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD COMMAND 
    ${CMAKE_COMMAND} -P 
        "${CMAKE_CURRENT_LIST_DIR}/cmake/copy_local_includes.cmake" 
        "${CMAKE_CURRENT_SOURCE_DIR}/include/" "security" "${QTZ_LOCAL_INCLUDES_DIR}"
)
endif()

# Link against dependencies
target_link_libraries(${PROJECT_NAME} PUBLIC Qt5::Core PRIVATE OpenSSL::SSL OpenSSL::Crypto)

# Install and export
include(GNUInstallDirs)

# pkg-config
configure_file("${PROJECT_NAME}.pc.in" "${PROJECT_NAME}.pc" @ONLY)

export(TARGETS ${PROJECT_NAME} FILE "${PROJECT_NAME}Targets.cmake")

install(TARGETS ${PROJECT_NAME}
    EXPORT "${PROJECT_NAME}Targets"
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/qtz/security"
    INCLUDES DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
)

install(DIRECTORY "include/" DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/qtz/security")

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(EXPORT "${PROJECT_NAME}Targets"
    FILE "${PROJECT_NAME}Targets.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/
)

install(FILES "cmake/${PROJECT_NAME}Config.cmake" 
    "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/
)

# pkg-config
configure_file("${PROJECT_NAME}.pc.in" "${PROJECT_NAME}.pc" @ONLY)

install(FILES "${CMAKE_CURRENT_BINARY_DIR}/${PROJECT_NAME}.pc"
    DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig
)

