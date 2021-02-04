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

# OS-dependent sources
set(OS_SOURCES )
if(WIN32)
    list(APPEND OS_SOURCES ${PROJECT_NAME}.rc)
endif()

# Define the library
add_library (${PROJECT_NAME} SHARED
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
    ${OS_SOURCES}
)

# Set properties
set_target_properties(${PROJECT_NAME} PROPERTIES 
    PROPERTIES VERSION 0.4.0
    PROPERTIES SOVERSION 0
    CXX_STANDARD 11
    DEBUG_POSTFIX "d"
    DEFINE_SYMBOL "QTZ_SECURITY_LIBRARY"
)

target_include_directories(${PROJECT_NAME}
    PUBLIC 
        $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}> 
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/src
)

# Link againsg dependencies
target_link_libraries(${PROJECT_NAME} PUBLIC Qt5::Core)

# Handle different names under different OSes
if(WIN32)
    target_link_libraries(${PROJECT_NAME} PUBLIC qca)
else()
    target_link_libraries(${PROJECT_NAME} PUBLIC qca-qt5)
endif()


# Install and export
include(GNUInstallDirs)

export(TARGETS ${PROJECT_NAME} FILE "${PROJECT_NAME}Targets.cmake")

install(TARGETS ${PROJECT_NAME}
    EXPORT "${PROJECT_NAME}Targets"
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)

install(DIRECTORY "include/" DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/qtz/security)

include(CMakePackageConfigHelpers)

write_basic_package_version_file(
    "${PROJECT_NAME}ConfigVersion.cmake"
    VERSION ${PROJECT_VERSION}
    COMPATIBILITY SameMajorVersion
)

install(EXPORT "${PROJECT_NAME}Targets"
    FILE "${PROJECT_NAME}Targets.cmake"
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/
    NAMESPACE Qtz::
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