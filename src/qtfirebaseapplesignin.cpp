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

#endif

} // namespace QtFirebaseAppleSignIn
