cmake_minimum_required(VERSION 3.19.0)

project(QtzSecurity VERSION 0.4.0 
    DESCRIPTION "Qtz Rapid Application Development Framework, Security Module"
    HOMEPAGE_URL "https://github.com/soroush/qtz-security"
    LANGUAGES CXX)

enable_testing()

add_subdirectory(lib)
add_subdirectory(test)