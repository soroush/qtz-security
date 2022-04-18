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
    // Read public key

    QFile publicKeyFile(workingDirectory.absoluteFilePath("rsa.public.pem"));
    if (!publicKeyFile.open(QIODevice::ReadOnly))
    {
        qDebug() << publicKeyFile.fileName() << "does not exist!";
        return EXIT_FAILURE;
    }
    const QString publicKey = QString::fromLatin1(publicKeyFile.readAll());

    // Test Signature verify
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
        QFile signature(workingDirectory.absoluteFilePath(fileName).replace("plain", "old-sign"));
        if (!signature.open(QIODevice::ReadOnly))
        {
            return EXIT_FAILURE;
        }
        const QByteArray plainData = plain.readAll();
        const QByteArray signatureData = signature.readAll();
        const bool result = Crypto::verifyRaw(plainData, signatureData, publicKey);

        assert(result == true);
    }
    return 0;
}
