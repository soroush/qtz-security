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
    // Read key and IV
    QFile keyFile(workingDirectory.absoluteFilePath("key.bin"));
    if (!keyFile.open(QIODevice::ReadOnly))
    {
        qDebug() << workingDirectory.absoluteFilePath("key.bin") << "does not exist!";
        return EXIT_FAILURE;
    }
    const QByteArray key = keyFile.readAll();

    QFile ivFile(workingDirectory.absoluteFilePath("iv.bin"));
    if (!ivFile.open(QIODevice::ReadOnly))
    {
        return EXIT_FAILURE;
    }
    const QByteArray iv = ivFile.readAll();

    // Test Decrypt
    workingDirectory.setNameFilters(QStringList("cypher-*.bin"));
    workingDirectory.setFilter(QDir::Files | QDir::NoDotAndDotDot | QDir::NoSymLinks);
    const QStringList fileList = workingDirectory.entryList();
    for (const QString& fileName : fileList)
    {
        QFile cipher(workingDirectory.absoluteFilePath(fileName));
        if (!cipher.open(QIODevice::ReadOnly))
        {
            return EXIT_FAILURE;
        }
        // Encrypt
        const QByteArray cypherData = cipher.readAll();
        const QByteArray plainData = Crypto::decryptRawData(cypherData, key, iv);
        QFile decrypted(workingDirectory.absoluteFilePath(fileName).replace("cypher", "decrypted"));
        if (!decrypted.open(QIODevice::WriteOnly))
        {
            return EXIT_FAILURE;
        }
        decrypted.write(plainData);
    }
    // Check validity
    workingDirectory.setNameFilters(QStringList("plain-*.bin"));
    for (const QString& fileName : fileList)
    {
        QFile plain(workingDirectory.absoluteFilePath(fileName));
        if (!plain.open(QIODevice::ReadOnly))
        {
            return EXIT_FAILURE;
        }
        QFile decrypted(workingDirectory.absoluteFilePath(fileName).replace("plain", "decrypted"));
        if (!decrypted.open(QIODevice::ReadOnly))
        {
            return EXIT_FAILURE;
        }
        // Compare
        const QByteArray plainData = plain.readAll();
        const QByteArray decryptedData = decrypted.readAll();
        assert(plainData == decryptedData);
    }
    return 0;
}
