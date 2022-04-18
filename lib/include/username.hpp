#ifndef QTZ_USERNAME_HPP
#define QTZ_USERNAME_HPP

#include "identity.hpp"
#include <QString>

class Username : public Identity
{
public:
    explicit Username(const QString& username = "");
    Username(const Username& other) = default;
    ~Username() = default;

    void set(const QString& username);
    QString get() const;

private:
    QString m_username;
};

#endif // QTZ_USERNAME_HPP
