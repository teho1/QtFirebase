#ifndef QTFIREBASE_AUTH_HELPERS_H
#define QTFIREBASE_AUTH_HELPERS_H

#include <QString>
#include <QStringList>

/// Platform-neutral auth helpers (unit-tested; only Firebase's header-only
/// auth/types.h, no SDK libraries).
namespace QtFirebaseAuthHelpers {

/// Masks an email for logs: "teemu@example.com" -> "t***@example.com".
/// Strings without '@' become "***"; an empty string stays empty.
QString maskEmail(const QString &email);

/// True when Sign in with Apple tokens must be revoked before deleting the
/// account (App Store Review Guideline 5.1.1(v)): the user has the apple.com
/// provider and a fresh authorization code from Apple is available.
bool shouldRevokeAppleToken(const QStringList &providerIds, const QString &authorizationCode);

/// Maps a Firebase iOS SDK FIRAuthErrorCode (NSError code in FIRAuthErrorDomain)
/// to the firebase::auth::AuthError the C++ futures report, for the codes the
/// federated failure handling and its user-facing messages distinguish.
/// Unknown codes map to kAuthErrorFailure.
int authErrorFromFirAuthErrorCode(long code);

} // namespace QtFirebaseAuthHelpers

#endif // QTFIREBASE_AUTH_HELPERS_H
