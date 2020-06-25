#ifndef QTZ_SECURITY_KEYRING_HPP
#define QTZ_SECURITY_KEYRING_HPP

#include <QByteArray>
#include "qtz-security.hpp"

class QTZ_SECURITY_SHARED_EXPORT KeyRing {
public:
    KeyRing() = default;
    virtual ~KeyRing() = default;
    virtual QByteArray provideRawKey() const = 0;
    virtual QByteArray provideRawIV() const = 0;
    QString provideKey() const;
    QString provideIV() const;
    virtual size_t keySize() const = 0;
    static KeyRing* defaultKeyRing();
};

class DefaultKeyRing : public KeyRing {
public:
    DefaultKeyRing() = default;
    QByteArray provideRawKey() const override;
    QByteArray provideRawIV() const override;
    size_t keySize() const override;
};

#endif // QTZ_SECURITY_KEYRING_HPP
