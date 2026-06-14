#include "qtfirebasegooglesignin.h"

#include "qtfirebaseauth.h"

#include <QMetaObject>

namespace QtFirebaseGoogleSignIn {

namespace {

void deliverOnAuthThread(QtFirebaseAuth *auth, GoogleSignInCallback callback,
                         bool success, const QString &idToken, const QString &accessToken,
                         const QString &errorMessage)
{
    if (!auth || !callback)
        return;
    QMetaObject::invokeMethod(auth, [callback, success, idToken, accessToken, errorMessage]() {
        callback(success, idToken, accessToken, errorMessage);
    }, Qt::QueuedConnection);
}

} // namespace

#if !defined(Q_OS_ANDROID) && !defined(Q_OS_IOS)

void requestSignIn(QtFirebaseAuth *auth, GoogleSignInCallback callback)
{
    deliverOnAuthThread(auth, callback, false, QString(), QString(),
                        QStringLiteral("Google Sign-In is only available on iOS and Android."));
}

#endif

} // namespace QtFirebaseGoogleSignIn
