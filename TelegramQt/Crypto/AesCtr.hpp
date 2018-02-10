#ifndef TELEGRAM_AES_CTR_HPP
#define TELEGRAM_AES_CTR_HPP

#include "telegramqt_global.h"

#include <QByteArray>

namespace Telegram {

namespace Crypto {

class TELEGRAMQT_EXPORT AesCtrContext
{
public:
    explicit AesCtrContext();
    static constexpr int KeySize = 32;
    static constexpr int IvecSize = 16;
    static constexpr int EcountSize = 16;

    QByteArray key() const { return m_key; }
    bool setKey(const QByteArray &key);

    QByteArray ivec() const { return m_ivec; }
    bool setIVec(const QByteArray &iv);

    bool hasKey() const { return !m_key.isEmpty(); }

    QByteArray ecount() const { return m_ecount; }
    quint32 num() const { return m_num; }

    QByteArray crypt(const QByteArray &in);
    bool crypt(const QByteArray &in, QByteArray *out);

    // The context description is needed only for debug
    void setDescription(const QByteArray &desc) { m_description = desc; }
protected:
    QByteArray m_key;
    QByteArray m_ivec;
    QByteArray m_ecount;
    quint32 m_num = 0;
    QByteArray m_description;
};

} // Crypto

} // Telegram

#endif // TELEGRAM_AES_CTR_HPP
