/*
   Copyright (C) 2018 Alexandr Akulich <akulichalexander@gmail.com>

   This file is a part of TelegramQt library.

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 2.1 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Lesser General Public License for more details.

 */

#include "RpcLayer.hpp"

#include "CRawStream.hpp"
#include "SendPackageHelper.hpp"
#include "Utils.hpp"
#include "TLValues.hpp"

#ifdef DEVELOPER_BUILD
#include "AbridgedLength.hpp"
#include "Debug_p.hpp"
#endif

#include <QLoggingCategory>

namespace Telegram {

BaseRpcLayer::BaseRpcLayer(QObject *parent) :
    QObject(parent)
{
}

void BaseRpcLayer::setSendPackageHelper(BaseSendPackageHelper *helper)
{
    m_sendHelper = helper;
}

bool BaseRpcLayer::processPackage(const QByteArray &package)
{
    if (package.size() < 24) {
        return false;
    }
#ifdef BASE_RPC_IO_DEBUG
    qDebug() << "Read" << package.length() << "bytes";
#endif
    const quint64 *authKeyIdBytes = reinterpret_cast<const quint64*>(package.constData());
    const quint64 authKeyId = *authKeyIdBytes;
    if (!verifyAuthKey(authKeyId)) {
        qDebug() << Q_FUNC_INFO << "Incorrect auth id.";
#ifdef NETWORK_LOGGING
        QTextStream str(m_logFile);
        str << QDateTime::currentDateTime().toString(QLatin1String("yyyyMMdd HH:mm:ss:zzz")) << QLatin1Char('|');
        str << QLatin1String("pln|");
        str << QString(QLatin1String("size: %1|")).arg(input.length(), 4, 10, QLatin1Char('0'));
        str << QLatin1Char('|');
        str << package.toHex();
        str << endl;
        str.flush();
#endif
        return false;
    }
    // Encrypted Message
    const QByteArray messageKey = package.mid(8, 16);
#ifdef BASE_RPC_IO_DEBUG
    qWarning() << "key:" << messageKey.toHex();
#endif
    const QByteArray data = package.mid(24);
    const SAesKey key = getDecryptionAesKey(messageKey);
    const QByteArray decryptedData = Utils::aesDecrypt(data, key).left(data.length());
    return processDecryptedPackage(decryptedData);
}

SAesKey BaseRpcLayer::generateAesKey(const QByteArray &messageKey, int x) const
{
    // MTProto v2
    const QByteArray authKey = m_sendHelper->authKey();
    QByteArray sha256_a = Utils::sha256(messageKey + authKey.mid(x, 36));
    QByteArray sha256_b = Utils::sha256(authKey.mid(40 + x, 36) + messageKey);
    const QByteArray key = sha256_a.left(8) + sha256_b.mid(8, 16) + sha256_a.mid(24, 8);
    const QByteArray iv  = sha256_b.left(8) + sha256_a.mid(8, 16) + sha256_b.mid(24, 8);
    return SAesKey(key, iv);
}

bool BaseRpcLayer::verifyAuthKey(quint64 authKeyId)
{
    return authKeyId == m_sendHelper->authId();
}

quint64 BaseRpcLayer::sendPackage(const QByteArray &buffer, SendMode mode)
{
    if (!m_sendHelper->authId()) {
        qCritical() << Q_FUNC_INFO << "Auth key is not set!";
        return 0;
    }
    QByteArray encryptedPackage;
    QByteArray messageKey;
    quint64 messageId = m_sendHelper->newMessageId(mode);
    qDebug() << Q_FUNC_INFO << "Send message" << TLValue::firstFromArray(buffer) << "with id" << messageId;
    {
        m_sequenceNumber = m_contentRelatedMessages * 2 + 1;
        ++m_contentRelatedMessages;
        CRawStream stream(CRawStream::WriteOnly);
        const quint32 contentLength = buffer.length();

        stream << m_sendHelper->serverSalt();
        stream << m_sessionId;
        stream << messageId;
        stream << m_sequenceNumber;
        stream << contentLength;
        stream << buffer;
        quint32 packageLength = stream.getData().length();
        if ((packageLength) % 16) {
            QByteArray randomPadding;
            randomPadding.resize(16 - (packageLength % 16));
            Utils::randomBytes(&randomPadding);
            packageLength += randomPadding.size();
            stream << randomPadding;
        }
        messageKey = Utils::sha1(stream.getData()).mid(4);
        const SAesKey key = getEncryptionAesKey(messageKey);
        encryptedPackage = Utils::aesEncrypt(stream.getData(), key).left(packageLength);
    }
    CRawStream output(CRawStream::WriteOnly);
    output << m_sendHelper->authId();
    output << messageKey;
    output << encryptedPackage;
    m_sendHelper->sendPackage(output.getData());
    return messageId;
}

} // Telegram namespace
