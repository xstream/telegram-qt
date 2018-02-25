#ifndef TELEGRAM_CLIENT_BACKEND_HPP
#define TELEGRAM_CLIENT_BACKEND_HPP

#include <QObject>
#include <QVector>

#include "CAppInformation.hpp"

struct TLDcOption;

namespace Telegram {

class PendingOperation;

//class AppInformation : public CAppInformation { };

namespace Client {

class Connection;
class Client;
class Settings;
class AccountStorage;
class DataStorage;
class RpcLayer;
class PendingAuthOperation;

class Backend : public QObject
{
    Q_OBJECT
public:
    explicit Backend(Client *parent);

    RpcLayer *rpcLayer();

    PendingOperation *connectToServer();
    PendingAuthOperation *signIn();
    PendingOperation *getDcConfig();

    Connection *createConnection(const TLDcOption &dcInfo);
    Connection *mainConnection();

    void setMainConnection(Connection *connection);

    CAppInformation *m_appInformation = nullptr;
    Client *m_client; // Parent
    Settings *m_settings;
    AccountStorage *m_accountStorage;
    DataStorage *m_dataStorage;
    Connection *m_mainConnection = nullptr;

    PendingAuthOperation *m_authOperation = nullptr;
    PendingOperation *m_getDcConfigOperation = nullptr;

    bool m_signedIn = false;

protected Q_SLOTS:
    void onConnectOperationFinished(PendingOperation *operation);
};

} // Client namespace

} // Telegram namespace

#endif // TELEGRAM_CLIENT_BACKEND_HPP
