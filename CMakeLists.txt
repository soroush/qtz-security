cmake_minimum_required(VERSION 3.1.0)

project(QtzSecurity VERSION 0.4.0 
    DESCRIPTION "Qtz Rapid Application Development Framework, Security Module"
    HOMEPAGE_URL "https://github.com/soroush/qtz-security"
    LANGUAGES CXX)

set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTORCC ON)
set(CMAKE_AUTOUIC ON)

if(CMAKE_VERSION VERSION_LESS "3.7.0")
    set(CMAKE_INCLUDE_CURRENT_DIR ON)
endif()

# Check for dependencies
find_package(Qt5 COMPONENTS Core REQUIRED)
if(WIN32)
find_package(qca CONFIG REQUIRED)
else()
find_package(Qca-qt5 CONFIG REQUIRED)
endif()
# Include directories
include_directories("include")

# OS-dependent sources
set(OS_SOURCES )
if(WIN32)
    list(APPEND OS_SOURCES QtzSecurity.rc)
endif()

# Define the library
add_library (QtzSecurity SHARED
    src/virtual-machine-detector.cpp
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
    include/virtual-machine-detector.hpp
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

# Add 'd' suffix to debug builds
set_property(TARGET QtzSecurity PROPERTY DEBUG_POSTFIX d)

# Set version
set_target_properties(QtzSecurity PROPERTIES VERSION 0.4.0)
set_target_properties(QtzSecurity PROPERTIES SOVERSION 0)

# pkg-config
configure_file(QtzSecurity.pc.in QtzSecurity.pc @ONLY)

# Define symbol exporter
target_compile_definitions(QtzSecurity PRIVATE -DQTZ_SECURITY_LIBRARY)
target_compile_features(QtzSecurity PRIVATE cxx_std_11)

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
target_link_libraries(QtzSecurity PUBLIC Qt5::Core)

# Handle different names under different OSes
if(WIN32)
target_link_libraries(QtzSecurity PRIVATE qca)
else()
target_link_libraries(QtzSecurity PRIVATE qca-qt5)
endif()
