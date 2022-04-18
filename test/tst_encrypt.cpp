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

    // Test Encryption
    workingDirectory.setNameFilters(QStringList("plain-*.bin"));
    workingDirectory.setFilter(QDir::Files | QDir::NoDotAndDotDot | QDir::NoSymLinks);
    const QStringList fileList = workingDirectory.entryList();
    for (const QString& fileName : fileList)
    {
        QFile plain(workingDirectory.absoluteFilePath(fileName));
        if (!plain.open(QIODevice::ReadOnly))
        {
            return EXIT_FAILURE;
        }
        // Encrypt
        const QByteArray plainData = plain.readAll();
        const QByteArray cypherData = Crypto::encryptRawData(plainData, key, iv);
        QFile cypher(workingDirectory.absoluteFilePath(fileName).replace("plain", "encrypt"));
        if (!cypher.open(QIODevice::WriteOnly))
        {
            return EXIT_FAILURE;
        }
        cypher.write(cypherData);
    }
    // Check validity
    workingDirectory.setNameFilters(QStringList("cypher-*.bin"));
    for (const QString& fileName : fileList)
    {
        QFile cypher(workingDirectory.absoluteFilePath(fileName));
        if (!cypher.open(QIODevice::ReadOnly))
        {
            return EXIT_FAILURE;
        }
        QFile encrypted(workingDirectory.absoluteFilePath(fileName).replace("cypher", "encrypt"));
        if (!encrypted.open(QIODevice::ReadOnly))
        {
            return EXIT_FAILURE;
        }
        // Compare
        const QByteArray cypherData = cypher.readAll();
        const QByteArray encryptedData = encrypted.readAll();
        assert(cypherData == encryptedData);
    }
    return 0;
}
