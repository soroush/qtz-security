#ifndef QTZ_BASIC_AUTHENTICATOR_HPP
#define QTZ_BASIC_AUTHENTICATOR_HPP

#include "authenticator.hpp"


/*
 * BasicAuthentication is the simplest type of authentication, through a username and a password.
 */

class BasicAuthenticator : public Authenticator
{
    Q_OBJECT
public:
    BasicAuthenticator(QObject* parent = nullptr);
    BasicAuthenticator(const BasicAuthenticator&) = default;
    ~BasicAuthenticator() = default;

    virtual bool authenticate(const Identity& id, const Token& token);
};

#endif // QTZ_BASIC_AUTHENTICATOR_HPP
