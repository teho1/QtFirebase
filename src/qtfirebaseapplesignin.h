#ifndef QTFIREBASE_APPLE_SIGNIN_H
#define QTFIREBASE_APPLE_SIGNIN_H

#include <functional>

#include <QString>

class QtFirebaseAuth;

namespace QtFirebaseAppleSignIn {

struct Result
{
    bool success = false;
    bool cancelled = false;
    QString idToken;
    QString rawNonce;
    // Apple returns the name and email only on the very first authorization.
    QString fullName;
    QString email;
    // Short-lived (5 min) code used only to revoke Apple tokens on account
    // deletion. Never log it or persist it.
    QString authorizationCode;
    QString errorMessage;
};

using AppleSignInCallback = std::function<void(const Result &result)>;
using RevokeCallback = std::function<void(bool success, const QString &errorMessage)>;

/// True when the native Sign in with Apple flow exists on this platform (iOS).
bool isAvailable();

/// Launch the native Sign in with Apple sheet and deliver the result to
/// @p callback on the Qt thread.
void requestSignIn(QtFirebaseAuth *auth, AppleSignInCallback callback);

/// Revoke the user's Sign in with Apple tokens through Firebase Auth
/// (FIRAuth revokeTokenWithAuthorizationCode). Must run while the user is
/// still signed in, i.e. before deleting the account. Delivers on the Qt thread.
void revokeToken(QtFirebaseAuth *auth, const QString &authorizationCode, RevokeCallback callback);

} // namespace QtFirebaseAppleSignIn

#endif // QTFIREBASE_APPLE_SIGNIN_H
