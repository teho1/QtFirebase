#ifndef QTFIREBASE_GOOGLE_SIGNIN_H
#define QTFIREBASE_GOOGLE_SIGNIN_H

#include <functional>

#include <QString>

class QtFirebaseAuth;
class QUrl;

namespace QtFirebaseGoogleSignIn {

using GoogleSignInCallback = std::function<void(
    bool success, const QString &idToken, const QString &accessToken, const QString &errorMessage)>;

/// Launch the platform Google Sign-In UI and deliver tokens to @p callback on the Qt thread.
void requestSignIn(QtFirebaseAuth *auth, GoogleSignInCallback callback);

#if defined(Q_OS_IOS)
/// Forward OAuth redirect URLs from the iOS application delegate.
bool handleOpenUrl(const QUrl &url);
#endif

} // namespace QtFirebaseGoogleSignIn

#endif // QTFIREBASE_GOOGLE_SIGNIN_H
