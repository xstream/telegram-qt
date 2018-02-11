#ifndef TELEGRAM_SERVER_DC_CONFIGURATION_HPP
#define TELEGRAM_SERVER_DC_CONFIGURATION_HPP

#include "TelegramNamespace.hpp"

#include <QVector>

namespace Telegram {

class DcConfiguration
{
public:
    QVector<DcOption> dcOptions;

    bool isValid() const { return !dcOptions.isEmpty(); }
};

} // Telegram

#endif // TELEGRAM_SERVER_DC_CONFIGURATION_HPP
