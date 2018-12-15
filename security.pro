QT += core gui sql xml
CONFIG += c++11 crypto

DEFINES += QTZ_SECURITY_LIBRARY

TEMPLATE = lib
VERSION = 0.4.0

CONFIG(release, debug|release){
    DESTDIR = ./release
    OBJECTS_DIR = release/.obj
    MOC_DIR = release/.moc
    RCC_DIR = release/.rcc
    UI_DIR = release/.ui
    BUILD = "release"
    BUILD_SUFFIX = ""
    TARGET = QtzSecurity
}

CONFIG(debug, debug|release){
    DESTDIR = ./debug
    OBJECTS_DIR = debug/.obj
    MOC_DIR = debug/.moc
    RCC_DIR = debug/.rcc
    UI_DIR = debug/.ui
    BUILD = "debug"
    BUILD_SUFFIX = "d"
    TARGET = QtzSecurityd
}

DEPENDPATH += .
INCLUDEPATH += .

unix {
    target.path = /usr/lib
    headers.path = /usr/include/qtz/security
    LINK_MAJ = ""
    CONFIG += create_pc create_prl no_install_prl
    QMAKE_PKGCONFIG_NAME = libqtz-security
    QMAKE_PKGCONFIG_DESCRIPTION = Qtz Security Library
    QMAKE_PKGCONFIG_PREFIX = $$INSTALLBASE
    QMAKE_PKGCONFIG_LIBDIR = $$target.path
    QMAKE_PKGCONFIG_INCDIR = $$headers.path
    QMAKE_PKGCONFIG_VERSION = $$VERSION
    QMAKE_PKGCONFIG_DESTDIR = pkgconfig
}
win32 {
    LIBS += -llibsslMD -llibcryptoMD
    LIBS += -lIphlpapi
    target.path = $$INSTALL_ROOT/lib
    headers.path = $$INSTALL_ROOT/include/qtz/security
    LINK_MAJ = "0"
    RC_FILE = QtzSecurity.rc
}

CONFIG(local){
    INCLUDEPATH += ../../
    QMAKE_LIBDIR += $$absolute_path("$$OUT_PWD/../core/$$BUILD")
    QMAKE_LIBDIR += $$absolute_path("$$OUT_PWD/../data/$$BUILD")
    LIBS += -lQtzData$${BUILD_SUFFIX}$${LINK_MAJ}
    LIBS += -lQtzCore$${BUILD_SUFFIX}$${LINK_MAJ}
}else {
    LIBS += -lQtzData$${BUILD_SUFFIX}$${LINK_MAJ}
    LIBS += -lQtzCore$${BUILD_SUFFIX}$${LINK_MAJ}
}

SOURCES += \
    authentication-source.cpp \
    authenticator.cpp \
    authorizer.cpp \
    identity.cpp \
    password.cpp \
    simple-authenticator.cpp \
    token.cpp \
    username.cpp \
    crypto.cpp \
    unique-machine-id.cpp \
    key-ring.cpp \
    license-manager.cpp \
    virtual-machine-detector.cpp

HEADERS += \
    authentication-source.hpp \
    authenticator.hpp \
    authorizer.hpp \
    identity.hpp \
    password.hpp \
    simple-authenticator.hpp \
    token.hpp \
    username.hpp \
    qtz-security.hpp \
    crypto.hpp \
    unique-machine-id.hpp \
    key-ring.hpp \
    license-manager.hpp \
    virtual-machine-detector.hpp

headers.files = $$HEADERS

INSTALLS += target
INSTALLS += headers
