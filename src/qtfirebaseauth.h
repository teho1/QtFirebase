#ifndef QTFIREBASE_AUTH_H
#define QTFIREBASE_AUTH_H

#include "qtfirebaseservice.h"
#include "firebase/auth.h"
#include <memory>

#ifdef QTFIREBASE_BUILD_AUTH
#include "src/qtfirebase.h"
#if defined(qFirebaseAuth)
#undef qFirebaseAuth
#endif
#define qFirebaseAuth (static_cast<QtFirebaseAuth *>(QtFirebaseAuth::instance()))

class QtFirebaseAuth : public QtFirebaseService
{
    Q_OBJECT
    Q_PROPERTY(bool running READ running NOTIFY runningChanged)
    Q_PROPERTY(bool signedIn READ signedIn NOTIFY signedInChanged)
    Q_PROPERTY(QString token READ token WRITE setToken NOTIFY tokenChanged FINAL)
    Q_PROPERTY(int action READ action NOTIFY actionChanged)
public:
    static QtFirebaseAuth *instance()
    {
        if(self == nullptr)
        {
            self = new QtFirebaseAuth(nullptr);
            qDebug() << self << "::instance" << "singleton";
        }
        return self;
    }
    ~QtFirebaseAuth() override;

    enum Error
    {
        ErrorNone = firebase::auth::kAuthErrorNone,
        ErrorUnimplemented = firebase::auth::kAuthErrorUnimplemented,
        ErrorFailure = firebase::auth::kAuthErrorFailure
    };
    Q_ENUM(Error)

    enum Action
    {
        ActionRegister,
        ActionSignIn,
        ActionSignInWithGoogle,
        ActionLinkWithGoogle,
        ActionFetchSignInMethods,
        ActionReauthenticate,
        ActionSignOut,
        ActionDeleteUser,
        ActionUpdateProfile,
        ActionPasswordReset,
        // Appended so existing numeric action ids stay stable.
        ActionSignInWithApple,
        ActionLinkWithApple
    };
    Q_ENUM(Action)



    QString token() const;
    void setToken(const QString &newToken);
    int action() const;

public slots:
    //Control
    void registerUser(const QString& email, const QString& pass);
    void signIn(const QString& email, const QString& pass);
    void signInWithGoogle();
    void linkWithGoogle();
    void reauthenticateWithGoogle();
    void signInWithApple();
    void linkWithApple();
    void reauthenticateWithApple();
    void fetchSignInMethodsForEmail(const QString& email);
    void signOut();
    void sendPasswordResetEmail(const QString& email);
    void deleteUser();
    // Forces a fresh ID token from Firebase (bypassing the local cache) and
    // emits tokenChanged() once it arrives. Used to recover from transient 401s.
    void refreshToken();
    void addAuthStateListener(firebase::auth::AuthStateListener* listener);
    void removeAuthStateListener(firebase::auth::AuthStateListener* listener);
    void addIdTokenListener(firebase::auth::IdTokenListener* listener);
    void removeIdTokenListener(firebase::auth::IdTokenListener* listener);

    //Status
    //Status
    bool signedIn() const;
    bool running() const;
    int errorId() const;
    QString errorMsg() const;

    //Data
    QString email() const;
    QString displayName() const;
    QString phoneNumber() const;
    bool emailVerified() const;
    bool isAuthVerified() const;
    bool isGoogleUser() const;
    bool isAppleUser() const;
    bool appleSignInAvailable() const;
    QString providerId() const;
    QString localizedErrorMessage(int errorId) const;
    // Log-safe form of an email address ("t***@example.com").
    QString maskEmail(const QString& email) const;
    QString photoUrl() const;
    QString uid() const;
    
    //Profile update
    void updateUserProfile(const QString& displayName, const QString& phoneNumber);

signals:
    void signedInChanged();
    void runningChanged();
    void completed(bool success, int actionId);
    void passwordResetEmailSent();
    void tokenChanged();
    void actionChanged();
    void signInMethodsFetched(const QStringList& methods);
    void accountLinkRequired(const QString& email, const QStringList& existingMethods);

protected:
    explicit QtFirebaseAuth(QObject *parent = nullptr);

private slots:
    void onAuthStateChanged();
    void onIdTokenChanged();
private:
    void setAction(int action);
    void clearError();
    void setComplete(bool complete);
    void setSignIn(bool value);
    void setError(int errId, const QString& errMsg = QString());
    void init() override;
    void onFutureEvent(QString eventId, firebase::FutureBase future) override;
    void getToken(bool forceRefresh = false);
    void completeGoogleSignInWithTokens(const QString& idToken, const QString& accessToken);
    void requestAppleSignIn();
    void completeAppleSignIn(const QString& idToken, const QString& rawNonce);
    void applyAppleFullNameIfMissing();
    bool hasProvider(const char* providerId) const;
    QStringList providerIds() const;
    void deleteCurrentUser();
    QString federatedProviderName() const;
    void handleFederatedSuccess(const QString& eventId);
    void handleFederatedFailure(const QString& eventId, int error);

    // Keep Firebase auth listeners alive so we get callbacks on session restore / token refresh.
    class AuthStateListenerImpl;
    class IdTokenListenerImpl;
    bool m_listenersInstalled = false;
    std::unique_ptr<AuthStateListenerImpl> m_authStateListener;
    std::unique_ptr<IdTokenListenerImpl> m_idTokenListener;

    static QtFirebaseAuth *self;
    firebase::auth::Auth* m_auth;

    bool m_complete;
    bool m_signedIn;
    int m_errId;
    QString m_errMsg;
    int m_action;
    QString m_token;
    QString m_pendingGoogleIdToken;
    QString m_pendingAppleIdToken;
    QString m_pendingAppleEmail;
    QString m_pendingAppleFullName;
    // Fresh Apple authorization code from the deletion reauth; memory only, never logged.
    QString m_appleAuthorizationCode;
    // "Google" or "Apple": provider of the current federated action, used in error messages.
    QString m_federatedProvider = QStringLiteral("Google");
    Q_DISABLE_COPY(QtFirebaseAuth)
};

#endif //QTFIREBASE_BUILD_AUTH

#endif // QTFIREBASE_AUTH_H




