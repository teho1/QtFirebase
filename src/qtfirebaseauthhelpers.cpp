#include "qtfirebaseauthhelpers.h"

#include "firebase/auth/types.h"

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

int authErrorFromFirAuthErrorCode(long code)
{
    namespace auth = ::firebase::auth;
    switch (code) {
    case 17004: return auth::kAuthErrorInvalidCredential;
    case 17005: return auth::kAuthErrorUserDisabled;
    case 17006: return auth::kAuthErrorOperationNotAllowed;
    case 17007: return auth::kAuthErrorEmailAlreadyInUse;
    case 17010: return auth::kAuthErrorTooManyRequests;
    case 17011: return auth::kAuthErrorUserNotFound;
    case 17012: return auth::kAuthErrorAccountExistsWithDifferentCredentials;
    case 17014: return auth::kAuthErrorRequiresRecentLogin;
    case 17015: return auth::kAuthErrorProviderAlreadyLinked;
    case 17020: return auth::kAuthErrorNetworkRequestFailed;
    case 17024: return auth::kAuthErrorUserMismatch;
    case 17025: return auth::kAuthErrorCredentialAlreadyInUse;
    // kAuthErrorMissingOrInvalidNonce is INTERNAL_EXPERIMENTAL in the public header.
    case 17094: return auth::kAuthErrorInvalidCredential;
    default: return auth::kAuthErrorFailure;
    }
}

} // namespace QtFirebaseAuthHelpers
