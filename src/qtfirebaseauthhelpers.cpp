#include "qtfirebaseauthhelpers.h"

namespace QtFirebaseAuthHelpers {

QString maskEmail(const QString &email)
{
    if (email.isEmpty())
        return QString();
    const qsizetype at = email.indexOf(QLatin1Char('@'));
    if (at <= 0)
        return QStringLiteral("***");
    return email.left(1) + QStringLiteral("***") + email.mid(at);
}

bool shouldRevokeAppleToken(const QStringList &providerIds, const QString &authorizationCode)
{
    return !authorizationCode.isEmpty() && providerIds.contains(QStringLiteral("apple.com"));
}

} // namespace QtFirebaseAuthHelpers
