#include "ClientBackend.hpp"
#include "ClientConnection.hpp"
#include "CClientTcpTransport.hpp"
#include "ClientSettings.hpp"
#include "AccountStorage.hpp"
#include "ClientConnection.hpp"
#include "Client.hpp"
#include "ClientRpcLayer.hpp"
#include "ClientRpcHelpLayer.hpp"
#include "DataStorage.hpp"

#include <QLoggingCategory>
#include <QTimer>

namespace Telegram {

namespace Client {

Backend::Backend(Client *parent) :
    QObject(parent),
    m_client(parent)
{
}

RpcLayer *Backend::rpcLayer()
{
    if (mainConnection()) {
        return mainConnection()->rpcLayer();
    }
    return nullptr;
}

PendingOperation *Backend::connectToServer()
{
    if (m_mainConnection && m_mainConnection->status() != Connection::Status::Disconnected) {
        return PendingOperation::failOperation<PendingOperation>({
                                                                     { QStringLiteral("text"), QStringLiteral("Connection is already in progress") }
                                                                 });
    }

    if (!m_mainConnection) {
        Connection *connection = new Connection(this);
        connection->rpcLayer()->setAppInformation(m_appInformation);
        setMainConnection(connection);

        TcpTransport *transport = new TcpTransport(connection);
        connection->setTransport(transport);
    }

    if (m_accountStorage->hasMinimalDataSet()) {
        m_mainConnection->setDcOption(m_accountStorage->dcInfo());
        m_mainConnection->setAuthKey(m_accountStorage->authKey());
    } else {
        m_mainConnection->setDcOption(m_settings->serverConfiguration().first());
        m_mainConnection->setAuthKey(QByteArray());
    }
    m_mainConnection->setServerRsaKey(m_settings->serverRsaKey());
    return m_mainConnection->connectToDc();
}

PendingAuthOperation *Backend::signIn()
{
    if (!m_authOperation) {
        m_authOperation = new PendingAuthOperation(this);
    }

    if (m_signedIn) {
        m_authOperation->setDelayedFinishedWithError({
                                                       { QStringLiteral("text"), QStringLiteral("Already signed in") }
                                                   });
        return m_authOperation;
    }
    if (!m_settings || !m_settings->isValid()) {
        qWarning() << "Invalid settings";
        m_authOperation->setDelayedFinishedWithError({
                                                       { QStringLiteral("text"), QStringLiteral("Invalid settings") }
                                                   });
        return m_authOperation;
    }

    // Transport?

/*  1 ) Establish TCP connection
    2a) if there is no key in AccountStorage, use DH layer to get it
    2b) use the key from AccountStorage
    -3) try to get self phone     (postponed)
    -4) if error, report an error (postponed)
    5a) if there is no phone number in AccountStorage, emit phoneRequired()
    6b) use phone from AccountStorage
     7) API Call authSendCode()
     8) If error 401 SESSION_PASSWORD_NEEDED:
     9)     API Call accountGetPassword() -> TLAccountPassword(salt)
    10)     API Call authCheckPassword( Utils::sha256(salt + password + salt) )
    11) API Call authSignIn()

     Request phone number

     Request auth code
     Request password

     Done!
  */

//    if (!m_private->m_appInfo || !m_private->m_appInfo->isValid()) {
//        qWarning() << "CTelegramCore::connectToServer(): App information is null or is not valid.";
//        return false;
//    }

//    m_private->m_dispatcher->setAppInformation(m_private->m_appInfo);
//    return m_private->m_dispatcher->connectToServer();
    // connectToServer(),
    // checkPhoneNumber()

    m_authOperation->setBackend(this);

    if (!m_accountStorage->phoneNumber().isEmpty()) {
        m_authOperation->setPhoneNumber(m_accountStorage->phoneNumber());
    }

    if (!mainConnection()) {
        m_authOperation->runAfter(connectToServer());
        return m_authOperation;
    }
    m_authOperation->setRunMethod(&PendingAuthOperation::requestAuthCode);
    m_authOperation->startLater();

    connect(m_authOperation, &PendingOperation::succeeded, [this]() {
        m_signedIn = true;
        emit m_client->signedInChanged(m_signedIn);
    });
    return m_authOperation;
}

PendingOperation *Backend::getDcConfig()
{
    if (m_getDcConfigOperation) {
        return m_getDcConfigOperation;
    }
    m_getDcConfigOperation = mainConnection()->rpcLayer()->help()->getConfig();
    return m_getDcConfigOperation;
}

Connection *Backend::createConnection(const TLDcOption &dcOption)
{
    qDebug() << Q_FUNC_INFO << dcOption.id << dcOption.ipAddress << dcOption.port;

    Connection *connection = new Connection(this);
    connection->setDcOption(dcOption);
    connection->rpcLayer()->setAppInformation(m_appInformation);

    // if transport TCP then


//    connection->setDcInfo(dcInfo);
//    connection->setDeltaTime(m_deltaTime);

//    connect(connection, &CTelegramConnection::connectionFailed, this, &CTelegramDispatcher::onConnectionFailed);
//    connect(connection, &CTelegramConnection::authStateChanged, this, &CTelegramDispatcher::onConnectionAuthChanged);
//    connect(connection, &CTelegramConnection::statusChanged, this, &CTelegramDispatcher::onConnectionStatusChanged);
//    connect(connection, &CTelegramConnection::dcConfigurationReceived, this, &CTelegramDispatcher::onDcConfigurationUpdated);
//    connect(connection, &CTelegramConnection::actualDcIdReceived, this, &CTelegramDispatcher::onConnectionDcIdUpdated);
//    connect(connection, &CTelegramConnection::newRedirectedPackage, this, &CTelegramDispatcher::onPackageRedirected);

//    connect(connection, &CTelegramConnection::usersReceived, this, &CTelegramDispatcher::onUsersReceived);
//    connect(connection, &CTelegramConnection::channelsParticipantsReceived, this, &CTelegramDispatcher::onChannelsParticipantsReceived);
//    for (CTelegramModule *module : m_modules) {
//        module->onNewConnection(connection);
//    }

    return connection;
}

Connection *Backend::mainConnection()
{
    return m_mainConnection;
}

void Backend::setMainConnection(Connection *connection)
{
    m_mainConnection = connection;
    connect(m_mainConnection, &BaseConnection::statusChanged, [this](Connection::Status status) {
        switch (status) {
        case Connection::Status::Authenticated:
        case Connection::Status::Signed:
            m_accountStorage->setAuthKey(m_mainConnection->authKey());
            m_accountStorage->setAuthId(m_mainConnection->authId());
            break;
        default:
            break;
        }
    });
}

void Backend::onConnectOperationFinished(PendingOperation *operation)
{
    if (!operation->isSucceeded()) {
        return;
    }
    if (!m_dataStorage->serverConfiguration().isValid()) {
        getDcConfig();
    }
}

} // Client namespace

} // Telegram namespace
