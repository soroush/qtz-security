#include <cassert>
#include <iostream>
#include <random>

#include <crypto.hpp>

#include <QDebug>
#include <QDir>
#include <QFile>

int main(int argc, char const* argv[])
{
    QDir workingDirectory = QDir{argv[1]};
    workingDirectory.cd("data");
    if (workingDirectory.exists() == false)
    {
        return EXIT_FAILURE;
    }
    // Read private key
    QFile privateKeyFile(workingDirectory.absoluteFilePath("rsa.private.pem"));
    if (!privateKeyFile.open(QIODevice::ReadOnly))
    {
        qDebug() << privateKeyFile.fileName() << "does not exist!";
        return EXIT_FAILURE;
    }
    const QString privateKey = QString::fromLatin1(privateKeyFile.readAll());

    // Test Signing
    workingDirectory.setNameFilters(QStringList("plain-*.bin"));
    workingDirectory.setFilter(QDir::Files | QDir::NoDotAndDotDot | QDir::NoSymLinks);
    QStringList fileList = workingDirectory.entryList();
    for (const QString& fileName : fileList)
    {
        QFile plain(workingDirectory.absoluteFilePath(fileName));
        if (!plain.open(QIODevice::ReadOnly))
        {
            return EXIT_FAILURE;
        }
        // Sign
        const QByteArray plainData = plain.readAll();
        const QByteArray cypherData = Crypto::signRaw(plainData, privateKey, QString{});
        QFile signature(workingDirectory.absoluteFilePath(fileName).replace("plain", "new-sign"));
        if (!signature.open(QIODevice::WriteOnly))
        {
            return EXIT_FAILURE;
        }
        signature.write(cypherData);
        signature.close();
    }
    // Compare with existing signatures
    workingDirectory.setNameFilters(QStringList("old-sign*.bin"));
    fileList = workingDirectory.entryList();
    for (const QString& fileName : fileList)
    {
        // Read old sign
        QFile oldSign(workingDirectory.absoluteFilePath(fileName));
        if (!oldSign.open(QIODevice::ReadOnly))
        {
            return EXIT_FAILURE;
        }
        const QByteArray oldSignData = oldSign.readAll();
        // Read new sign
        QFile newSign(workingDirectory.absoluteFilePath(fileName).replace("old-sign", "new-sign"));
        if (!newSign.open(QIODevice::ReadOnly))
        {
            return EXIT_FAILURE;
        }
        const QByteArray newSignData = newSign.readAll();
        // Compare
        assert(newSignData == oldSignData);
    }
    return 0;
}
