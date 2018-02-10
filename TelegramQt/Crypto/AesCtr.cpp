#include "AesCtr.hpp"

#include "AesCtr.hpp"

#include <openssl/aes.h>
extern "C" {
#include <openssl/modes.h>
}

#include <QLoggingCategory>

namespace Telegram {

namespace Crypto {

AesCtrContext::AesCtrContext()
{
    m_ecount = QByteArray(EcountSize, char(0));
}

bool AesCtrContext::setKey(const QByteArray &key)
{
    if (key.size() != KeySize) {
        return false;
    }
    m_key = key;
    return true;
}

bool AesCtrContext::setIVec(const QByteArray &iv)
{
    if (iv.size() != IvecSize) {
        return false;
    }
    m_ivec = iv;
    return true;
}

QByteArray AesCtrContext::crypt(const QByteArray &in)
{
    QByteArray out;
    if (crypt(in, &out)) {
        return out;
    }
    return QByteArray();
}

bool AesCtrContext::crypt(const QByteArray &in, QByteArray *out)
{
    out->resize(in.size());
    union {
        char *ivecData;
        unsigned char *ivecSsl[16];
    };
    ivecData = m_ivec.data();
    union {
        char *ecountData;
        unsigned char *ecountSsl[16];
    };
    ecountData = m_ecount.data();

#ifdef DEVELOPER_BUILD
    qDebug().noquote() << QStringLiteral("Crypt 0x%1 (%2) bytes on ").arg(in.size(), 4, 16, QLatin1Char('0')).arg(in.size()) << m_description << "context" << this;
    qDebug() << "Key:" << m_key.toHex() << "Ivec:" << m_ivec.toHex() << "Ecount:" << m_ecount.toHex();
#endif
    AES_KEY aes;
    AES_set_encrypt_key(reinterpret_cast<const unsigned char*>(m_key.constData()), 256, &aes);
    CRYPTO_ctr128_encrypt(reinterpret_cast<const uchar*>(in.constData()), reinterpret_cast<uchar*>(out->data()), in.size(), &aes, *ivecSsl, *ecountSsl, &m_num, (block128_f) AES_encrypt);
    return true;
}

} // Crypto

} // Telegram
