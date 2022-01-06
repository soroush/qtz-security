cmake_minimum_required(VERSION 3.19.0)

project(QtzSecurity VERSION 0.4.0 
    DESCRIPTION "Qtz Rapid Application Development Framework, Security Module"
    HOMEPAGE_URL "https://github.com/soroush/qtz-security"
    LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

# Check for dependencies
find_package(Qt5 COMPONENTS Core REQUIRED)
find_package(Qca CONFIG REQUIRED)

# Include directories
include_directories("include")

# Define the library
add_library (QtzSecurity SHARED
    # src/virtual-machine-detector.cpp
    src/username.cpp
    src/unique-machine-id.cpp
    src/token.cpp
    src/simple-authenticator.cpp
    src/password.cpp
    src/license-manager.cpp
    src/key-ring.cpp
    src/identity.cpp
    src/crypto.cpp
    src/authorizer.cpp
    src/authenticator.cpp
    src/authentication-source.cpp
    # Headers
    include/simple-authenticator.hpp
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
    ${OS_SOURCES})

# Set properties
set_target_properties(QtzSecurity PROPERTIES 
    VERSION 0.4.0
    SOVERSION 0
    DEBUG_POSTFIX d
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED TRUE
    DEFINE_SYMBOL QTZ_SECURITY_LIBRARY
)
# pkg-config
configure_file(QtzSecurity.pc.in QtzSecurity.pc @ONLY)

# Copy headers for local builds
if(QTZ_LOCAL_BUILD)
add_custom_command(TARGET QtzSecurity POST_BUILD COMMAND 
    ${CMAKE_COMMAND} -P 
        "${CMAKE_CURRENT_LIST_DIR}/../cmake/copy_local_includes.cmake" 
        "${CMAKE_CURRENT_SOURCE_DIR}/include/" "security" "${QTZ_LOCAL_INCLUDES_DIR}")
endif()

# Install and export
include(GNUInstallDirs)
target_include_directories(QtzSecurity PUBLIC  
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include/>  
    $<INSTALL_INTERFACE:include/>
)

install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qtz/security)

install(TARGETS QtzSecurity
    EXPORT QtzSecurityConfig
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    PUBLIC_HEADER DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

export(TARGETS QtzSecurity FILE QtzSecurityConfig.cmake)

install(EXPORT QtzSecurityConfig
    FILE QtzSecurityConfig.cmake
    NAMESPACE Qtz::
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/QtzSecurity.pc 
        DESTINATION ${CMAKE_INSTALL_DATAROOTDIR}/pkgconfig)

# Link againsg dependencies
target_link_libraries(QtzSecurity Qt5::Core qca)
