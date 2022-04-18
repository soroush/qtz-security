#include "crypto.hpp"

#include <cstring>

#include <QCryptographicHash>
#include <QDebug>

#include <openssl/bio.h>
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

QByteArray Crypto::decryptRawData(const QByteArray& input, const QByteArray& rawKey, const QByteArray& rawIV)
{
    const unsigned char* ciphertext = reinterpret_cast<const unsigned char*>(input.constData());
    const int ciphertext_len = input.size();
    const unsigned char* key = reinterpret_cast<const unsigned char*>(rawKey.constData());
    const unsigned char* iv = reinterpret_cast<const unsigned char*>(rawIV.constData());
    unsigned char* plaintext = (unsigned char*)OPENSSL_malloc(ciphertext_len);
    int plaintext_len = 0;
    QByteArray plainData;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto handle_error;

    // Perform decryption
    int error_code = EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);
    if (error_code != 1)
        goto handle_error;

    int len = 0;
    error_code = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    if (error_code != 1)
        goto handle_error;

    plaintext_len = len;
    error_code = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    if (error_code != 1)
        goto handle_error;

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);

    // Construct the output, return
    plaintext_len += len;
    plainData = QByteArray(reinterpret_cast<const char*>(plaintext), plaintext_len);
    OPENSSL_clear_free(plaintext, plaintext_len);
    return plainData;

handle_error:
    OPENSSL_clear_free(plaintext, plaintext_len);
    return QByteArray{};
}

QString Crypto::decrypt(const QString& base64Cipher, const QByteArray& rawKey, const QByteArray& rawIV)
{
    QByteArray rawCipher = QByteArray::fromBase64(base64Cipher.toLatin1());
    QByteArray rawPlain = decryptRawData(rawCipher, rawKey, rawIV);
    return QString::fromUtf8(rawPlain);
}

QString Crypto::decrypt(const QString& base64Cipher, const QString& base64Key, const QString& base64IV)
{
    QByteArray rawKey = QByteArray::fromBase64(base64Key.toLatin1());
    QByteArray rawIV = QByteArray::fromBase64(base64IV.toLatin1());
    QByteArray rawCipher = QByteArray::fromBase64(base64Cipher.toLatin1());
    QByteArray rawPlain = decryptRawData(rawCipher, rawKey, rawIV);
    return QString::fromUtf8(rawPlain);
}

QByteArray Crypto::encryptRawData(const QByteArray& input, const QByteArray& rawKey, const QByteArray& rawIV)
{
    const unsigned char* plaintext = reinterpret_cast<const unsigned char*>(input.constData());
    const int plaintext_len = input.size();
    const unsigned char* key = reinterpret_cast<const unsigned char*>(rawKey.constData());
    const unsigned char* iv = reinterpret_cast<const unsigned char*>(rawIV.constData());
    const int block = EVP_CIPHER_block_size(EVP_aes_128_cbc());
    const int initial_cipher_length = plaintext_len + (block - (plaintext_len % block));
    unsigned char* ciphertext = new unsigned char[initial_cipher_length];
    int ciphertext_len = 0;
    QByteArray cipherData;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto handle_error;

    // Perform encryption
    int error_code = EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv);

    if (error_code != 1)
        goto handle_error;

    int len = 0;
    error_code = EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    if (error_code != 1)
        goto handle_error;

    ciphertext_len = len;
    error_code = EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    if (error_code != 1)
        goto handle_error;

    // Cleanup
    EVP_CIPHER_CTX_free(ctx);

    // Prepare the output
    ciphertext_len += len;
    cipherData = QByteArray(reinterpret_cast<const char*>(ciphertext), ciphertext_len);
    OPENSSL_clear_free(ciphertext, ciphertext_len);
    return cipherData;

handle_error:
    OPENSSL_clear_free(ciphertext, sizeof(ciphertext));
    return QByteArray{};
}

QString Crypto::encrypt(const QString& input, const QByteArray& rawKey, const QByteArray& rawIV)
{
    QByteArray base64Cipher = encryptRawData(input.toUtf8(), rawKey, rawIV).toBase64();
    return QString::fromLatin1(base64Cipher);
}

QString Crypto::encrypt(const QString& input, const QString& base64Key, const QString& base64IV)
{
    QByteArray rawKey = QByteArray::fromBase64(base64Key.toLatin1());
    QByteArray rawIV = QByteArray::fromBase64(base64IV.toLatin1());
    QByteArray base64Cipher = encryptRawData(input.toUtf8(), rawKey, rawIV).toBase64();
    return QString::fromLatin1(base64Cipher);
}

QByteArray Crypto::signRaw(const QByteArray& input, const QString& PEM, const QString& passphrase)
{
    // Prepare inputs and default outputs
    const unsigned char* msg = reinterpret_cast<const unsigned char*>(input.constData());
    unsigned char* signed_message = nullptr;
    QByteArray signature;

    // Read the PEM key data
    const QByteArray PEM_data = PEM.toLatin1();
    const QByteArray password_data = passphrase.toLatin1();
    BIO* bo = BIO_new(BIO_s_mem());
    BIO_write(bo, PEM_data.constData(), PEM_data.size());
    EVP_PKEY* pkey = nullptr;
    if (passphrase.isEmpty())
        pkey = PEM_read_bio_PrivateKey(bo, &pkey, nullptr, nullptr);
    else
        pkey = PEM_read_bio_PrivateKey(bo, &pkey, nullptr, (void*)(password_data.constData()));
    BIO_free(bo);
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);

    // Prepare signature algorithm
    int errcode = 0;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    if (mdctx == nullptr)
        goto handle_error;

    // Perform signing
    errcode = EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey);
    if (errcode != 1)
        goto handle_error;

    errcode = EVP_DigestSignUpdate(mdctx, msg, input.size());
    if (errcode != 1)
        goto handle_error;

    // Calculate the signature length
    std::size_t msg_len = 0;
    errcode = EVP_DigestSignFinal(mdctx, NULL, &msg_len);
    if (errcode != 1)
        goto handle_error;

    // Allocate the signature space, perform the final signing
    signed_message = (unsigned char*)OPENSSL_malloc(msg_len);
    errcode = EVP_DigestSignFinal(mdctx, signed_message, &msg_len);
    if (errcode != 1)
        goto handle_error;

    // Cleanup and return
    EVP_MD_CTX_free(mdctx);

    signature = QByteArray((char*)signed_message, msg_len);
    OPENSSL_clear_free(signed_message, msg_len);
    return signature;

handle_error:
    OPENSSL_clear_free(signed_message, sizeof(signed_message));
    return QByteArray{};
}

QString Crypto::sign(const QString& input, const QString& PEM, const QString& passphrase)
{
    QByteArray signature = signRaw(input.toUtf8(), PEM, passphrase);
    return QString::fromLatin1(signature.toBase64());
}

bool Crypto::verifyRaw(const QByteArray& message, const QByteArray& signature, const QString& PEM)
{
    // Prepare the inputs
    const unsigned char* msg = reinterpret_cast<const unsigned char*>(message.constData());
    const unsigned char* sig = reinterpret_cast<const unsigned char*>(signature.constData());
    // Read the PEM key data
    const QByteArray PEM_data = PEM.toLatin1();
    BIO* bo = BIO_new(BIO_s_mem());
    BIO_write(bo, PEM_data.constData(), PEM_data.size());
    EVP_PKEY* pkey = nullptr;
    PEM_read_bio_PUBKEY(bo, &pkey, nullptr, nullptr);
    BIO_free(bo);
    RSA* rsa = EVP_PKEY_get1_RSA(pkey);

    // Prepare signature algorithm
    int errcode = 0;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_create();
    if (mdctx == nullptr)
        return false;

    errcode = EVP_DigestVerifyInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey);
    if (errcode != 1)
        return false;

    errcode = EVP_DigestVerifyUpdate(mdctx, msg, message.size());
    if (errcode != 1)
        return false;

    const int final_check = EVP_DigestVerifyFinal(mdctx, sig, signature.size());

    EVP_MD_CTX_free(mdctx);

    return final_check == 1;
}

bool Crypto::verify(const QString& message, const QString& base64Signature, const QString& certificate)
{
    return verifyRaw(message.toUtf8(), QByteArray::fromBase64(base64Signature.toLatin1()), certificate);
}

QByteArray Crypto::hash(const QByteArray& data)
{
    return QCryptographicHash::hash(data, QCryptographicHash::Keccak_512);
}
