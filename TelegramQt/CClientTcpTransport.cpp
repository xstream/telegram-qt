/*
   Copyright (C) 2017 Alexandr Akulich <akulichalexander@gmail.com>

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

#include "CClientTcpTransport.hpp"
#include "CRawStream.hpp"
#include "Utils.hpp"
#include "AesCtr.hpp"

#include <QTcpSocket>

#include <QLoggingCategory>

namespace Telegram {

namespace Client {

Q_LOGGING_CATEGORY(c_loggingTranport, "telegram.client.transport", QtWarningMsg)

static const quint8 c_abridgedVersionByte = 0xef;
static const quint32 c_intermediateVersionBytes = 0xeeeeeeeeu;
static const quint32 c_obfucsatedProcotolIdentifier = 0xefefefefu;

TcpTransport::TcpTransport(QObject *parent) :
    CTcpTransport(parent)
{
    setSocket(new QTcpSocket(this));
}

void TcpTransport::initObfucsation()
{
    // prepare random part
    const QVector<quint32> headerFirstWordBlackList = {
        0x44414548u, 0x54534f50u, 0x20544547u, 0x20544547u, c_intermediateVersionBytes,
    };
    const QVector<quint32> headerSecondWordBlackList = {
        0x0,
    };

    quint32 firstByte;
    // The first word must not concide with any of previously known session first words
    do {
        firstByte = Utils::randomBytes<quint32>();
    } while (headerFirstWordBlackList.contains(firstByte) || ((firstByte & 0xffu) == c_abridgedVersionByte));

    quint32 secondByte;
    // The same about the second word.
    do {
        secondByte = Utils::randomBytes<quint32>();
    } while (headerSecondWordBlackList.contains(secondByte));

    const QByteArray aesSourceData = Utils::getRandomBytes(48);
    setCryptoKeysSourceData(aesSourceData, DirectIsWriteReversedIsRead);

    // first, second, AES,                    , protocol id, random 4 bytes
    //      4      8                          56            60
    // xxxx | xxxx | xxxx ... xxxx (48 bytes) | 0xefefefefU | xxxx //
    // 64 bytes in total
    const quint32 trailingRandom = Utils::randomBytes<quint32>();

    CRawStream raw(CRawStream::WriteOnly);
    raw << firstByte;
    raw << secondByte;
    raw << aesSourceData;
    m_socket->write(raw.getData());
    raw << c_obfucsatedProcotolIdentifier;
    raw << trailingRandom;
    QByteArray encrypted = m_writeAesContext->crypt(raw.getData());
    m_socket->write(encrypted.mid(56, 8));
}

void TcpTransport::initAbridgedVersion()
{
    qCDebug(c_loggingTranport) << "Start session in Abridged format";
    m_socket->putChar(char(0xef));
}

bool TcpTransport::setProxy(const QNetworkProxy &proxy)
{
    if (m_socket->isOpen()) {
        qCWarning(c_loggingTranport) << Q_FUNC_INFO << "Unable to set proxy on open socket";
        return false;
    }
    m_socket->setProxy(proxy);
    return true;
}

void TcpTransport::writeEvent()
{
    if (Q_LIKELY(m_sessionType != Unknown)) {
        return;
    }
    initObfucsation();
    setSessionType(Obfuscated);
}

} // Client

} // Telegram
