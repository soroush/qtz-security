#include "username.hpp"

Username::Username(const QString& username)
    : m_username(username)
{
}

void Username::set(const QString& username)
{
    m_username = username;
}

QString Username::get() const
{
    return m_username;
}
