#include "basic-authenticator.hpp"
#include "username.hpp"
#include "password.hpp"
#include <stdexcept>

BasicAuthenticator::BasicAuthenticator(QObject* parent)
    : Authenticator(parent)
{
}

bool BasicAuthenticator::authenticate(const Identity& id, const Token& token)
{
    try
    {
        const Username& username = dynamic_cast<const Username&>(id);
        const Password& password = dynamic_cast<const Password&>(token);
    }
    catch (std::bad_cast& e)
    {
        // Handle Errors
        return false;
    }
}