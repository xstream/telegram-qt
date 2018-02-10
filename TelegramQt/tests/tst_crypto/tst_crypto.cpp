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

#include <QObject>

#include "AesCtr.hpp"

#include <QTest>
#include <QDebug>

using namespace Telegram;

class tst_crypto : public QObject
{
    Q_OBJECT
private slots:
    void aesCtrContext();
    void aesCtrContext2();
    void reference();
};

void tst_crypto::aesCtrContext()
{
    const QByteArray nonce = QByteArray::fromHex(QByteArrayLiteral("c6c021e092aff8f9452114b9fbd4a919"
                                                                   "a27a256821dd1e7213c562f26f94883c"
                                                                   "4c7449b74fc8fb96d4c0727f2043d69f"
                                                                   "cc94eb639cc9486aefefefef39175b65"));
    const QByteArray source = nonce.mid(8, 48);
    const QByteArray key = source.left(Telegram::Crypto::AesCtrContext::KeySize);
    const QByteArray iv = source.mid(Telegram::Crypto::AesCtrContext::KeySize, Telegram::Crypto::AesCtrContext::IvecSize);

    Telegram::Crypto::AesCtrContext sendContext;
    sendContext.setKey(key);
    sendContext.setIVec(iv);
    Telegram::Crypto::AesCtrContext receiveContext = sendContext;

    const QByteArray encrypted = sendContext.crypt(nonce);
    const QByteArray decrypted = receiveContext.crypt(encrypted);

    qDebug() << encrypted.toHex();
    qDebug() << decrypted.toHex();
    QCOMPARE(nonce.toHex(), decrypted.toHex());

    const QByteArray pack2 = QByteArrayLiteral("a27a256821dd1e7213c562f26f94883ca27a256821dd1e7213c562f26f94883c");

    const QByteArray encrypted2 = sendContext.crypt(pack2);
    const QByteArray decrypted2 = receiveContext.crypt(encrypted2);
    qDebug() << encrypted2.toHex();
    qDebug() << decrypted2.toHex();
    QCOMPARE(pack2.toHex(), decrypted2.toHex());

    const QByteArray words = QByteArrayLiteral("word1");
    const QByteArray encrypted3 = sendContext.crypt(words);
    const QByteArray decrypted31 = receiveContext.crypt(encrypted3.left(3));
    const QByteArray decrypted32 = receiveContext.crypt(encrypted3.mid(3));
    qDebug() << encrypted3.toHex();
    qDebug() << decrypted31.toHex();
    qDebug() << decrypted32.toHex();
    qDebug() << decrypted31 + decrypted32;
}

void tst_crypto::aesCtrContext2()
{
    const QByteArray key = QByteArray::fromHex(QByteArrayLiteral("452114b9fbd4a919a27a256821dd1e72"
                                                                 "13c562f26f94883c4c7449b74fc8fb96"));
    const QByteArray iv1 = QByteArray::fromHex(QByteArrayLiteral("d4c0727f2043d69fcc94eb639cc9486a"));
    const QByteArray ec1 = QByteArray::fromHex(QByteArrayLiteral("00000000000000000000000000000000"));
    const QByteArray dec1 = QByteArray::fromHex(QByteArrayLiteral("c6c021e092aff8f9452114b9fbd4a919"
                                                                  "a27a256821dd1e7213c562f26f94883c"
                                                                  "4c7449b74fc8fb96d4c0727f2043d69f"
                                                                  "cc94eb639cc9486aefefefef39175b65"));
    const QByteArray enc1 = QByteArray::fromHex(QByteArrayLiteral("03d6cd84351bfb08df7faa6e2c5b727b"
                                                                  "6db368b1880ce7d6e1ccec708fbe098a"
                                                                  "cee6e68f6c0358efcaf9e08dfe593f16"
                                                                  "dd484f07170c583a61b2c3998de93b24"));
    const QByteArray iv2 = QByteArray::fromHex(QByteArrayLiteral("d4c0727f2043d69fcc94eb639cc9486e"));
    const QByteArray ec2 = QByteArray::fromHex(QByteArrayLiteral("11dca4648bc510508e5d2c76b4fe6041"));

    Telegram::Crypto::AesCtrContext sendContext;
    sendContext.setKey(key);
    sendContext.setIVec(iv1);
    Telegram::Crypto::AesCtrContext receiveContext = sendContext;

    QCOMPARE(sendContext.ivec().toHex(), iv1.toHex());
    QCOMPARE(sendContext.ecount().toHex(), ec1.toHex());

    const QByteArray encrypted = sendContext.crypt(dec1);
    QCOMPARE(encrypted.toHex(), enc1.toHex());
    QCOMPARE(sendContext.ivec().toHex(), iv2.toHex());
    QCOMPARE(sendContext.ecount().toHex(), ec2.toHex());

    const QByteArray decrypted = receiveContext.crypt(encrypted);
    QCOMPARE(decrypted.toHex(), dec1.toHex());
}

#include <openssl/aes.h>
extern "C" {
#include <openssl/modes.h>
}

struct CtrState {
    static constexpr int KeySize = 32;
    static constexpr int IvecSize = 16;
    static constexpr int EcountSize = 16;

    uchar ivec[IvecSize] = { 0 };
    quint32 num = 0;
    uchar ecount[EcountSize] = { 0 };

    QByteArray getIvec() const
    {
        return QByteArray::fromRawData(reinterpret_cast<const char*>(ivec), CtrState::IvecSize);
    }

    QByteArray getEcount() const
    {
        return QByteArray::fromRawData(reinterpret_cast<const char*>(ecount), CtrState::EcountSize);
    }
};

QByteArray aesCtrCrypt(const QByteArray &in, quint32 len, const void *key, CtrState *state)
{
    qDebug() << "state:" << state;
    qDebug() << "in:" << in.toHex();
    QByteArray out = in;
    AES_KEY aes;
    AES_set_encrypt_key(static_cast<const uchar*>(key), 256, &aes);

    static_assert(CtrState::IvecSize == AES_BLOCK_SIZE, "Wrong size of ctr ivec!");
    static_assert(CtrState::EcountSize == AES_BLOCK_SIZE, "Wrong size of ctr ecount!");

    QByteArray keyHex = QByteArray::fromRawData(reinterpret_cast<const char*>(key), CtrState::KeySize);
    qDebug() << "origin key:" << keyHex.toHex();

    QByteArray ivecHex = state->getIvec();
    qDebug() << "origin ivec:" << ivecHex.toHex();

    QByteArray ecountHex = state->getEcount();
    qDebug() << "origin ecount:" << ecountHex.toHex();

    CRYPTO_ctr128_encrypt(reinterpret_cast<const uchar*>(in.constData()), reinterpret_cast<uchar*>(out.data()), len, &aes, state->ivec, state->ecount, &state->num, (block128_f) AES_encrypt);
    return out;
}

void tst_crypto::reference()
{
    const QByteArray key = QByteArray::fromHex(QByteArrayLiteral("452114b9fbd4a919a27a256821dd1e72"
                                                                 "13c562f26f94883c4c7449b74fc8fb96"));
    const QByteArray iv1 = QByteArray::fromHex(QByteArrayLiteral("d4c0727f2043d69fcc94eb639cc9486a"));
    const QByteArray ec1 = QByteArray::fromHex(QByteArrayLiteral("00000000000000000000000000000000"));
    const QByteArray dec1 = QByteArray::fromHex(QByteArrayLiteral("c6c021e092aff8f9452114b9fbd4a919"
                                                                  "a27a256821dd1e7213c562f26f94883c"
                                                                  "4c7449b74fc8fb96d4c0727f2043d69f"
                                                                  "cc94eb639cc9486aefefefef39175b65"));
    const QByteArray enc1 = QByteArray::fromHex(QByteArrayLiteral("03d6cd84351bfb08df7faa6e2c5b727b"
                                                                  "6db368b1880ce7d6e1ccec708fbe098a"
                                                                  "cee6e68f6c0358efcaf9e08dfe593f16"
                                                                  "dd484f07170c583a61b2c3998de93b24"));
    const QByteArray iv2 = QByteArray::fromHex(QByteArrayLiteral("d4c0727f2043d69fcc94eb639cc9486e"));
    const QByteArray ec2 = QByteArray::fromHex(QByteArrayLiteral("11dca4648bc510508e5d2c76b4fe6041"));

    uchar _key[CtrState::KeySize];
    CtrState _sendState;
    CtrState _receiveState;

    memcpy(_key, key.constData(), CtrState::KeySize);
    memcpy(_sendState.ivec, iv1.constData(), CtrState::IvecSize);
    memcpy(_receiveState.ivec, iv1.constData(), CtrState::IvecSize);
    QCOMPARE(_sendState.getIvec().toHex(), iv1.toHex());
    QCOMPARE(_sendState.getEcount().toHex(), ec1.toHex());

    const QByteArray encrypted = aesCtrCrypt(dec1.constData(), 64, _key, &_sendState);
    QCOMPARE(encrypted.toHex(), enc1.toHex());
    QCOMPARE(_sendState.getIvec().toHex(), iv2.toHex());
    QCOMPARE(_sendState.getEcount().toHex(), ec2.toHex());

    const QByteArray decrypted = aesCtrCrypt(encrypted, 64, _key, &_receiveState);
    QCOMPARE(decrypted.toHex(), dec1.toHex());
}

QTEST_APPLESS_MAIN(tst_crypto)

#include "tst_crypto.moc"
