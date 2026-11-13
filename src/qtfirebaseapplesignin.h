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
    QString errorMessage;
};

using AppleSignInCallback = std::function<void(const Result &result)>;

/// True when the native Sign in with Apple flow exists on this platform (iOS).
bool isAvailable();

/// Launch the native Sign in with Apple sheet and deliver the result to
/// @p callback on the Qt thread.
void requestSignIn(QtFirebaseAuth *auth, AppleSignInCallback callback);

} // namespace QtFirebaseAppleSignIn

#endif // QTFIREBASE_APPLE_SIGNIN_H
