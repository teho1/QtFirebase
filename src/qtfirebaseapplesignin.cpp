#include "qtfirebaseapplesignin.h"

#include "qtfirebaseauth.h"

#include <QMetaObject>

namespace QtFirebaseAppleSignIn {

#if !defined(Q_OS_IOS)

bool isAvailable()
{
    return false;
}

void requestSignIn(QtFirebaseAuth *auth, AppleSignInCallback callback)
{
    if (!auth || !callback)
        return;
    QMetaObject::invokeMethod(auth, [callback]() {
        Result result;
        result.errorMessage = QStringLiteral("Sign in with Apple is only available on iOS.");
        callback(result);
    }, Qt::QueuedConnection);
}

void authenticateWithFirebase(QtFirebaseAuth *auth, FirebaseOperation operation,
                              const QString &idToken, const QString &rawNonce,
                              FirebaseCallback callback)
{
    Q_UNUSED(operation)
    Q_UNUSED(idToken)
    Q_UNUSED(rawNonce)
    if (!auth || !callback)
        return;
    QMetaObject::invokeMethod(auth, [callback]() {
        callback(firebase::auth::kAuthErrorFailure,
                 QStringLiteral("Sign in with Apple is only available on iOS."));
    }, Qt::QueuedConnection);
}

void revokeToken(QtFirebaseAuth *auth, const QString &authorizationCode, RevokeCallback callback)
{
    Q_UNUSED(authorizationCode)
    if (!auth || !callback)
        return;
    QMetaObject::invokeMethod(auth, [callback]() {
        callback(false, QStringLiteral("Sign in with Apple is only available on iOS."));
    }, Qt::QueuedConnection);
}

#endif

} // namespace QtFirebaseAppleSignIn
