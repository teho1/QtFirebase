#include "../qtfirebasegooglesignin.h"

#include "../qtfirebaseauth.h"

#include <androidextras.h>
#include <QtCore/private/qandroidextras_p.h>
#include <QJniObject>
#include <QMetaObject>

namespace QtFirebaseGoogleSignIn {

namespace {

constexpr int kGoogleSignInRequestCode = 9102;
GoogleSignInCallback g_pendingCallback;
QtFirebaseAuth *g_pendingAuth = nullptr;

void deliverOnAuthThread(bool success, const QString &idToken, const QString &accessToken,
                         const QString &errorMessage)
{
    QtFirebaseAuth *auth = g_pendingAuth;
    GoogleSignInCallback callback = g_pendingCallback;
    g_pendingAuth = nullptr;
    g_pendingCallback = nullptr;

    if (!auth || !callback)
        return;

    QMetaObject::invokeMethod(auth, [callback, success, idToken, accessToken, errorMessage]() {
        callback(success, idToken, accessToken, errorMessage);
    }, Qt::QueuedConnection);
}

} // namespace

extern "C" JNIEXPORT void JNICALL
Java_com_righthere2_android_GoogleSignInHelper_nativeGoogleSignInCompleted(
    JNIEnv * /*env*/, jclass /*clazz*/, jstring idToken, jstring accessToken, jstring errorMessage)
{
    const QString token = idToken ? QJniObject(idToken).toString() : QString();
    const QString access = accessToken ? QJniObject(accessToken).toString() : QString();
    const QString error = errorMessage ? QJniObject(errorMessage).toString() : QString();
    deliverOnAuthThread(error.isEmpty() && !token.isEmpty(), token, access, error);
}

void requestSignIn(QtFirebaseAuth *auth, GoogleSignInCallback callback)
{
    if (g_pendingCallback) {
        deliverOnAuthThread(false, QString(), QString(),
                            QStringLiteral("Google Sign-In is already in progress."));
        return;
    }

    g_pendingAuth = auth;
    g_pendingCallback = std::move(callback);

    const QJniObject intent = QJniObject::callStaticObjectMethod(
        "com/righthere2/android/GoogleSignInHelper",
        "createSignInIntent",
        "(Landroid/content/Context;)Landroid/content/Intent;",
        qtAndroidContext().object());

    if (!intent.isValid()) {
        deliverOnAuthThread(false, QString(), QString(),
                            QStringLiteral("Could not create Google Sign-In intent."));
        return;
    }

    QtAndroidPrivate::startActivity(intent, kGoogleSignInRequestCode,
        [](int requestCode, int /*resultCode*/, const QJniObject &data) {
            if (requestCode != kGoogleSignInRequestCode)
                return;

            QJniObject::callStaticMethod<void>(
                "com/righthere2/android/GoogleSignInHelper",
                "deliverSignInResult",
                "(Landroid/content/Intent;)V",
                data.isValid() ? data.object() : nullptr);
        });
}

} // namespace QtFirebaseGoogleSignIn
