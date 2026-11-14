#include "qtfirebaseauth.h"
#include "qtfirebasegooglesignin.h"
#include "qtfirebaseapplesignin.h"
#include "qtfirebaseauthhelpers.h"

#include <QJsonDocument>
#include <QJsonObject>

namespace auth = ::firebase::auth;

namespace {

QString emailFromIdToken(const QString &idToken)
{
    const QStringList parts = idToken.split(QLatin1Char('.'));
    if (parts.size() < 2)
        return QString();

    QByteArray payload = parts.at(1).toUtf8();
    const int padding = payload.size() % 4;
    if (padding > 0)
        payload.append(QByteArray(4 - padding, '='));

    const QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromBase64(payload));
    if (!doc.isObject())
        return QString();
    return doc.object().value(QStringLiteral("email")).toString();
}

const char kAppleProviderId[] = "apple.com";

// Event ids are "<service id>.auth.<operation>.<provider>"; compare the part after the service id.
QString authEventName(const QString &serviceId, const QString &eventId)
{
    return eventId.startsWith(serviceId) ? eventId.mid(serviceId.size()) : QString();
}

bool isFederatedSignInEvent(const QString &serviceId, const QString &eventId)
{
    const QString name = authEventName(serviceId, eventId);
    return name == QLatin1String(".auth.signin.google") || name == QLatin1String(".auth.signin.apple");
}

bool isFederatedReauthEvent(const QString &serviceId, const QString &eventId)
{
    const QString name = authEventName(serviceId, eventId);
    return name == QLatin1String(".auth.reauth.google") || name == QLatin1String(".auth.reauth.apple");
}

bool isFederatedEvent(const QString &serviceId, const QString &eventId)
{
    const QString name = authEventName(serviceId, eventId);
    return isFederatedSignInEvent(serviceId, eventId)
        || isFederatedReauthEvent(serviceId, eventId)
        || name == QLatin1String(".auth.link.google")
        || name == QLatin1String(".auth.link.apple");
}

bool isAppleEvent(const QString &eventId)
{
    return eventId.endsWith(QStringLiteral(".apple"));
}

} // namespace

QtFirebaseAuth *QtFirebaseAuth::self = nullptr;

class QtFirebaseAuth::AuthStateListenerImpl : public firebase::auth::AuthStateListener
{
public:
    explicit AuthStateListenerImpl(QtFirebaseAuth *owner) : m_owner(owner) {}
    void OnAuthStateChanged(firebase::auth::Auth * /*auth*/) override
    {
        if (!m_owner)
            return;
        QMetaObject::invokeMethod(m_owner, "onAuthStateChanged", Qt::QueuedConnection);
    }
private:
    QtFirebaseAuth *m_owner = nullptr;
};

class QtFirebaseAuth::IdTokenListenerImpl : public firebase::auth::IdTokenListener
{
public:
    explicit IdTokenListenerImpl(QtFirebaseAuth *owner) : m_owner(owner) {}
    void OnIdTokenChanged(firebase::auth::Auth * /*auth*/) override
    {
        if (!m_owner)
            return;
        QMetaObject::invokeMethod(m_owner, "onIdTokenChanged", Qt::QueuedConnection);
    }
private:
    QtFirebaseAuth *m_owner = nullptr;
};

QtFirebaseAuth::QtFirebaseAuth(QObject *parent)
    : QtFirebaseService(parent)
    , m_auth(nullptr)
    , m_complete(false)
    , m_signedIn(false)
    , m_errId(ErrorNone)
    , m_action(ActionSignIn)
{
    if(self == nullptr)
    {
        self = this;
        qInfo() << "[FIREBASE AUTH] QtFirebaseAuth singleton created";
    }
    startInit();
}

QtFirebaseAuth::~QtFirebaseAuth()
{
    if (m_auth && m_listenersInstalled) {
        if (m_authStateListener) {
            m_auth->RemoveAuthStateListener(m_authStateListener.get());
        }
        if (m_idTokenListener) {
            m_auth->RemoveIdTokenListener(m_idTokenListener.get());
        }
    }
    self = nullptr;
}

void QtFirebaseAuth::clearError()
{
    setError(ErrorNone);
}

void QtFirebaseAuth::setError(int errId, const QString &errMsg)
{
    m_errId = errId;
    m_errMsg = errMsg;
}

void QtFirebaseAuth::registerUser(const QString &email, const QString &pass)
{
    qInfo() << "[FIREBASE AUTH] registerUser called for email:" << maskEmail(email);
    if(running())
    {
        qInfo() << "[FIREBASE AUTH] registerUser: Already running, ignoring request";
        return;
    }

    clearError();
    setComplete(false);
    setAction(ActionRegister);
    qDebug() << "[FIREBASE AUTH] registerUser: Creating user with email and password";
    firebase::Future<auth::AuthResult> future =
        m_auth->CreateUserWithEmailAndPassword(email.toUtf8().constData(), pass.toUtf8().constData());

    qFirebase->addFuture(__QTFIREBASE_ID + QStringLiteral(".auth.register"), future);
    qDebug() << "[FIREBASE AUTH] registerUser: Future added, waiting for result";
}

void QtFirebaseAuth::deleteUser()
{
    if (running()) {
        qWarning() << "[FIREBASE AUTH] deleteUser: ignored — another auth action is in progress (running=false required)";
        return;
    }
    if (!signedIn()) {
        qWarning() << "[FIREBASE AUTH] deleteUser: failed — not signed in (sensitive op requires a current user)";
        setAction(ActionDeleteUser);
        setError(ErrorFailure, QStringLiteral("No signed-in Firebase user to delete"));
        setComplete(false);
        setComplete(true);
        return;
    }

    setAction(ActionDeleteUser);
    clearError();
    setComplete(false);

    // App Store Review Guideline 5.1.1(v): revoke Sign in with Apple tokens
    // while the user is still signed in, then delete. A revocation failure is
    // logged (never the code) and does not stop the deletion.
    const QString authorizationCode = m_appleAuthorizationCode;
    m_appleAuthorizationCode.clear();
    if (QtFirebaseAuthHelpers::shouldRevokeAppleToken(providerIds(), authorizationCode)) {
        qInfo() << "[FIREBASE AUTH] deleteUser: revoking Sign in with Apple tokens first";
        QtFirebaseAppleSignIn::revokeToken(this, authorizationCode,
            [this](bool success, const QString &errorMessage) {
                if (success)
                    qInfo() << "[FIREBASE AUTH] deleteUser: Apple tokens revoked";
                else
                    qWarning() << "[FIREBASE AUTH] deleteUser: Apple token revocation failed, deleting anyway:" << errorMessage;
                deleteCurrentUser();
            });
        return;
    }
    if (isAppleUser())
        qWarning() << "[FIREBASE AUTH] deleteUser: Apple user without a fresh authorization code; tokens not revoked";
    deleteCurrentUser();
}

// Revokes the Sign in with Apple tokens with the authorization code from the latest
// reauthentication, without deleting the user: the app's server deletes the account and
// the Firebase user afterwards (App Store Review Guideline 5.1.1(v)). Firebase needs the
// user to still exist for the revocation. Emits completed(success, ActionRevokeAppleToken).
void QtFirebaseAuth::revokeAppleToken()
{
    if (running()) {
        qWarning() << "[FIREBASE AUTH] revokeAppleToken: ignored — another auth action is in progress";
        return;
    }
    setAction(ActionRevokeAppleToken);
    clearError();
    setComplete(false);

    const QString authorizationCode = m_appleAuthorizationCode;
    m_appleAuthorizationCode.clear();
    if (!signedIn() || !QtFirebaseAuthHelpers::shouldRevokeAppleToken(providerIds(), authorizationCode)) {
        qWarning() << "[FIREBASE AUTH] revokeAppleToken: no signed-in Apple user with a fresh authorization code";
        setError(ErrorFailure, QStringLiteral("No Sign in with Apple authorization code to revoke"));
        setComplete(true);
        return;
    }
    QtFirebaseAppleSignIn::revokeToken(this, authorizationCode,
        [this](bool success, const QString &errorMessage) {
            if (success) {
                qInfo() << "[FIREBASE AUTH] revokeAppleToken: Apple tokens revoked";
            } else {
                qWarning() << "[FIREBASE AUTH] revokeAppleToken: revocation failed:" << errorMessage;
                setError(ErrorFailure, errorMessage);
            }
            setComplete(true);
        });
}

void QtFirebaseAuth::deleteCurrentUser()
{
    if (!m_auth || !m_auth->current_user().is_valid()) {
        qWarning() << "[FIREBASE AUTH] deleteUser: no signed-in Firebase user left to delete";
        setError(ErrorFailure, QStringLiteral("No signed-in Firebase user to delete"));
        setComplete(true);
        return;
    }
    qInfo() << "[FIREBASE AUTH] deleteUser: deleting current Firebase Auth user"
            << "uid:" << QString::fromStdString(m_auth->current_user().uid())
            << "email:" << maskEmail(QString::fromStdString(m_auth->current_user().email()));
    firebase::Future<void> future = m_auth->current_user().Delete();
    qFirebase->addFuture(__QTFIREBASE_ID + QStringLiteral(".auth.deleteUser"), future);
}

void QtFirebaseAuth::sendPasswordResetEmail(const QString &email)
{
    if(running())
        return;

    clearError();
    setAction(ActionPasswordReset);
    setComplete(false);
    firebase::Future<void> future =
        m_auth->SendPasswordResetEmail(email.toUtf8().constData());
    qFirebase->addFuture(__QTFIREBASE_ID + QStringLiteral(".auth.resetEmail"), future);
}



bool QtFirebaseAuth::signedIn() const
{
    return m_signedIn;
}

void QtFirebaseAuth::signIn(const QString &email, const QString &pass)
{
    qInfo() << "[FIREBASE AUTH] signIn called for email:" << maskEmail(email);
    if(running())
    {
        qInfo() << "[FIREBASE AUTH] signIn: Already running, ignoring request";
        return;
    }

    setAction(ActionSignIn);
    clearError();
    setComplete(false);

    if(signedIn())
    {
        qInfo() << "[FIREBASE AUTH] signIn: Already signed in, signing out first";
        signOut();
    }
    qInfo() << "[FIREBASE AUTH] signIn: Signing in with email and password";
    firebase::Future<auth::AuthResult> future =
        m_auth->SignInWithEmailAndPassword(email.toUtf8().constData(), pass.toUtf8().constData());

    qFirebase->addFuture(__QTFIREBASE_ID + QStringLiteral(".auth.signin"), future);
    qDebug() << "[FIREBASE AUTH] signIn: Future added, waiting for result";
}

void QtFirebaseAuth::signInWithGoogle()
{
    qInfo() << "[FIREBASE AUTH] signInWithGoogle called";
    if (running()) {
        qInfo() << "[FIREBASE AUTH] signInWithGoogle: Already running, ignoring request";
        return;
    }

    m_federatedProvider = QStringLiteral("Google");
    setAction(ActionSignInWithGoogle);
    clearError();
    setComplete(false);

    if (signedIn()) {
        qInfo() << "[FIREBASE AUTH] signInWithGoogle: Already signed in, signing out first";
        signOut();
    }

    QtFirebaseGoogleSignIn::requestSignIn(this,
        [this](bool success, const QString &idToken, const QString &accessToken, const QString &errorMessage) {
            if (!success) {
                qWarning() << "[FIREBASE AUTH] signInWithGoogle native failed:" << errorMessage;
                setError(ErrorFailure, errorMessage.isEmpty()
                    ? localizedErrorMessage(auth::kAuthErrorFailure)
                    : errorMessage);
                setComplete(true);
                return;
            }
            completeGoogleSignInWithTokens(idToken, accessToken);
        });
}

void QtFirebaseAuth::linkWithGoogle()
{
    qInfo() << "[FIREBASE AUTH] linkWithGoogle called";
    if (!signedIn()) {
        setAction(ActionLinkWithGoogle);
        setError(ErrorFailure, QStringLiteral("No signed-in Firebase user to link"));
        setComplete(false);
        setComplete(true);
        return;
    }
    if (running())
        return;

    m_federatedProvider = QStringLiteral("Google");
    setAction(ActionLinkWithGoogle);
    clearError();
    setComplete(false);

    QtFirebaseGoogleSignIn::requestSignIn(this,
        [this](bool success, const QString &idToken, const QString &accessToken, const QString &errorMessage) {
            if (!success) {
                setError(ErrorFailure, errorMessage.isEmpty()
                    ? localizedErrorMessage(auth::kAuthErrorFailure)
                    : errorMessage);
                setComplete(true);
                return;
            }
            completeGoogleSignInWithTokens(idToken, accessToken);
        });
}

void QtFirebaseAuth::reauthenticateWithGoogle()
{
    qInfo() << "[FIREBASE AUTH] reauthenticateWithGoogle called";
    if (!signedIn()) {
        setAction(ActionReauthenticate);
        setError(ErrorFailure, QStringLiteral("No signed-in Firebase user to reauthenticate"));
        setComplete(false);
        setComplete(true);
        return;
    }
    if (running())
        return;

    m_federatedProvider = QStringLiteral("Google");
    setAction(ActionReauthenticate);
    clearError();
    setComplete(false);

    QtFirebaseGoogleSignIn::requestSignIn(this,
        [this](bool success, const QString &idToken, const QString &accessToken, const QString &errorMessage) {
            if (!success) {
                setError(ErrorFailure, errorMessage.isEmpty()
                    ? localizedErrorMessage(auth::kAuthErrorFailure)
                    : errorMessage);
                setComplete(true);
                return;
            }
            completeGoogleSignInWithTokens(idToken, accessToken);
        });
}

void QtFirebaseAuth::fetchSignInMethodsForEmail(const QString &email)
{
    if (running())
        return;

    setAction(ActionFetchSignInMethods);
    clearError();
    setComplete(false);

    firebase::Future<auth::Auth::FetchProvidersResult> future =
        m_auth->FetchProvidersForEmail(email.toUtf8().constData());
    qFirebase->addFuture(__QTFIREBASE_ID + QStringLiteral(".auth.fetchproviders"), future);
}

void QtFirebaseAuth::completeGoogleSignInWithTokens(const QString &idToken, const QString &accessToken)
{
    m_pendingGoogleIdToken = idToken;

    const QByteArray idTokenUtf8 = idToken.toUtf8();
    const QByteArray accessTokenUtf8 = accessToken.toUtf8();
    const char *accessTokenCStr = accessTokenUtf8.isEmpty() ? nullptr : accessTokenUtf8.constData();

    auth::Credential credential =
        auth::GoogleAuthProvider::GetCredential(idTokenUtf8.constData(), accessTokenCStr);

    if (!credential.is_valid()) {
        setError(auth::kAuthErrorInvalidCredential, localizedErrorMessage(auth::kAuthErrorInvalidCredential));
        setComplete(true);
        return;
    }

    if (m_action == ActionReauthenticate) {
        firebase::Future<auth::AuthResult> future =
            m_auth->current_user().ReauthenticateAndRetrieveData(credential);
        qFirebase->addFuture(__QTFIREBASE_ID + QStringLiteral(".auth.reauth.google"), future);
        return;
    }

    if (m_action == ActionLinkWithGoogle) {
        firebase::Future<auth::AuthResult> future = m_auth->current_user().LinkWithCredential(credential);
        qFirebase->addFuture(__QTFIREBASE_ID + QStringLiteral(".auth.link.google"), future);
        return;
    }

    firebase::Future<auth::AuthResult> future = m_auth->SignInAndRetrieveDataWithCredential(credential);
    qFirebase->addFuture(__QTFIREBASE_ID + QStringLiteral(".auth.signin.google"), future);
}

void QtFirebaseAuth::signInWithApple()
{
    qInfo() << "[FIREBASE AUTH] signInWithApple called";
    if (running()) {
        qInfo() << "[FIREBASE AUTH] signInWithApple: Already running, ignoring request";
        return;
    }

    // Sign out before setting the action: signOut() completes its own ActionSignOut.
    if (signedIn()) {
        qInfo() << "[FIREBASE AUTH] signInWithApple: Already signed in, signing out first";
        signOut();
    }

    setAction(ActionSignInWithApple);
    clearError();
    setComplete(false);
    requestAppleSignIn();
}

void QtFirebaseAuth::linkWithApple()
{
    qInfo() << "[FIREBASE AUTH] linkWithApple called";
    if (!signedIn()) {
        setAction(ActionLinkWithApple);
        setError(ErrorFailure, QStringLiteral("No signed-in Firebase user to link"));
        setComplete(false);
        setComplete(true);
        return;
    }
    if (running())
        return;

    setAction(ActionLinkWithApple);
    clearError();
    setComplete(false);
    requestAppleSignIn();
}

void QtFirebaseAuth::reauthenticateWithApple()
{
    qInfo() << "[FIREBASE AUTH] reauthenticateWithApple called";
    if (!signedIn()) {
        setAction(ActionReauthenticate);
        setError(ErrorFailure, QStringLiteral("No signed-in Firebase user to reauthenticate"));
        setComplete(false);
        setComplete(true);
        return;
    }
    if (running())
        return;

    setAction(ActionReauthenticate);
    clearError();
    setComplete(false);
    requestAppleSignIn();
}

void QtFirebaseAuth::requestAppleSignIn()
{
    m_federatedProvider = QStringLiteral("Apple");
    m_pendingAppleIdToken.clear();
    m_pendingAppleEmail.clear();
    m_pendingAppleFullName.clear();
    m_appleAuthorizationCode.clear();

    QtFirebaseAppleSignIn::requestSignIn(this, [this](const QtFirebaseAppleSignIn::Result &result) {
        if (!result.success) {
            qWarning() << "[FIREBASE AUTH] Sign in with Apple native failed:" << result.errorMessage
                       << "cancelled:" << result.cancelled;
            if (result.cancelled)
                setError(auth::kAuthErrorCancelled, localizedErrorMessage(auth::kAuthErrorCancelled));
            else
                setError(ErrorFailure, result.errorMessage.isEmpty()
                    ? localizedErrorMessage(auth::kAuthErrorFailure)
                    : result.errorMessage);
            setComplete(true);
            return;
        }
        m_pendingAppleEmail = result.email;
        m_pendingAppleFullName = result.fullName;
        // Only account-deletion reauth needs the code (to revoke tokens); keep it nowhere else.
        if (m_action == ActionReauthenticate)
            m_appleAuthorizationCode = result.authorizationCode;
        completeAppleSignIn(result.idToken, result.rawNonce);
    });
}

void QtFirebaseAuth::completeAppleSignIn(const QString &idToken, const QString &rawNonce)
{
    m_pendingAppleIdToken = idToken;

    // Not auth::OAuthProvider::GetCredential: on iOS it sends an empty
    // access_token and Firebase rejects it ("Invalid OAuth response from apple.com").
    QtFirebaseAppleSignIn::FirebaseOperation operation = QtFirebaseAppleSignIn::FirebaseOperation::SignIn;
    QString eventId = __QTFIREBASE_ID + QStringLiteral(".auth.signin.apple");
    if (m_action == ActionReauthenticate) {
        operation = QtFirebaseAppleSignIn::FirebaseOperation::Reauthenticate;
        eventId = __QTFIREBASE_ID + QStringLiteral(".auth.reauth.apple");
    } else if (m_action == ActionLinkWithApple) {
        operation = QtFirebaseAppleSignIn::FirebaseOperation::Link;
        eventId = __QTFIREBASE_ID + QStringLiteral(".auth.link.apple");
    }

    QtFirebaseAppleSignIn::authenticateWithFirebase(this, operation, idToken, rawNonce,
        [this, eventId](int authError, const QString &errorMessage) {
            if (authError == auth::kAuthErrorNone) {
                qInfo() << "[FIREBASE AUTH] Federated auth operation succeeded for event:" << eventId;
                clearError();
                handleFederatedSuccess(eventId);
            } else {
                qWarning() << "[FIREBASE AUTH] Apple Firebase auth failed:" << authError << errorMessage;
                // Unmapped errors fall back to errorMsg() in localizedErrorMessage().
                setError(authError, errorMessage);
                handleFederatedFailure(eventId, authError);
            }
            setComplete(true);
        });
}

void QtFirebaseAuth::applyAppleFullNameIfMissing()
{
    // Apple shares the user's name only on the first authorization and Firebase
    // does not copy it into the profile, so persist it while we still have it.
    const QString fullName = m_pendingAppleFullName;
    m_pendingAppleFullName.clear();
    if (fullName.isEmpty() || !m_auth || !m_auth->current_user().is_valid())
        return;
    if (!m_auth->current_user().display_name().empty())
        return;

    auth::User::UserProfile profile;
    const QByteArray nameUtf8 = fullName.toUtf8();
    profile.display_name = nameUtf8.constData();
    // Not routed through qFirebase->addFuture: a failure here must not turn the
    // successful sign-in into an error.
    m_auth->current_user().UpdateUserProfile(profile).OnCompletion([](const firebase::Future<void> &result) {
        if (result.error() != auth::kAuthErrorNone)
            qWarning() << "[FIREBASE AUTH] Apple display name update failed:" << result.error() << result.error_message();
    });
}

bool QtFirebaseAuth::isAuthVerified() const
{
    if (!signedIn())
        return false;
    // Google and Apple verify the email themselves (incl. Apple private relay addresses).
    if (isGoogleUser() || isAppleUser())
        return true;
    return emailVerified();
}

bool QtFirebaseAuth::isAppleUser() const
{
    return hasProvider(kAppleProviderId);
}

bool QtFirebaseAuth::appleSignInAvailable() const
{
    return QtFirebaseAppleSignIn::isAvailable();
}

bool QtFirebaseAuth::hasProvider(const char *providerId) const
{
    if (!signedIn() || !m_auth)
        return false;

    const std::vector<auth::UserInfoInterface> providers = m_auth->current_user().provider_data();
    for (const auth::UserInfoInterface &provider : providers) {
        if (provider.provider_id() == providerId)
            return true;
    }
    return false;
}

QStringList QtFirebaseAuth::providerIds() const
{
    QStringList ids;
    if (!signedIn() || !m_auth)
        return ids;
    for (const auth::UserInfoInterface &provider : m_auth->current_user().provider_data())
        ids.append(QString::fromStdString(provider.provider_id()));
    return ids;
}

QString QtFirebaseAuth::maskEmail(const QString &email) const
{
    return QtFirebaseAuthHelpers::maskEmail(email);
}

QString QtFirebaseAuth::federatedProviderName() const
{
    return m_federatedProvider;
}

bool QtFirebaseAuth::isGoogleUser() const
{
    return hasProvider(auth::GoogleAuthProvider::kProviderId);
}

QString QtFirebaseAuth::providerId() const
{
    if (!signedIn() || !m_auth)
        return QString();

    const std::vector<auth::UserInfoInterface> providers = m_auth->current_user().provider_data();
    for (const auth::UserInfoInterface &provider : providers) {
        const std::string id = provider.provider_id();
        if (!id.empty())
            return QString::fromStdString(id);
    }
    return QString();
}

QString QtFirebaseAuth::localizedErrorMessage(int errorId) const
{
    switch (static_cast<auth::AuthError>(errorId)) {
    case auth::kAuthErrorNone:
        return QString();
    case auth::kAuthErrorAccountExistsWithDifferentCredentials:
        return QStringLiteral("Tällä sähköpostilla on jo tili toisella kirjautumistavalla. "
                              "Kirjaudu ensin aiemmalla tavalla ja linkitä %1-tili sen jälkeen.")
            .arg(federatedProviderName());
    case auth::kAuthErrorEmailAlreadyInUse:
        return QStringLiteral("Sähköpostiosoite on jo käytössä.");
    case auth::kAuthErrorInvalidEmail:
        return QStringLiteral("Sähköpostiosoite on virheellinen.");
    case auth::kAuthErrorWrongPassword:
        return QStringLiteral("Virheellinen salasana.");
    case auth::kAuthErrorUserNotFound:
        return QStringLiteral("Käyttäjää ei löytynyt.");
    case auth::kAuthErrorUserDisabled:
        return QStringLiteral("Käyttäjätili on poistettu käytöstä.");
    case auth::kAuthErrorTooManyRequests:
        return QStringLiteral("Liian monta yritystä. Yritä myöhemmin uudelleen.");
    case auth::kAuthErrorNetworkRequestFailed:
        return QStringLiteral("Verkkovirhe. Tarkista yhteys ja yritä uudelleen.");
    case auth::kAuthErrorRequiresRecentLogin:
        return QStringLiteral("Toiminto vaatii uuden kirjautumisen.");
    case auth::kAuthErrorCredentialAlreadyInUse:
        return QStringLiteral("%1-tili on jo linkitetty toiseen käyttäjään.").arg(federatedProviderName());
    case auth::kAuthErrorProviderAlreadyLinked:
        return QStringLiteral("%1 on jo linkitetty tähän tiliin.").arg(federatedProviderName());
    case auth::kAuthErrorCancelled:
        return QStringLiteral("%1-kirjautuminen peruutettiin.").arg(federatedProviderName());
    case auth::kAuthErrorOperationNotAllowed:
        return QStringLiteral("%1-kirjautuminen ei ole käytössä. Ota se käyttöön Firebase Consolessa.")
            .arg(federatedProviderName());
    default:
        if (!errorMsg().isEmpty())
            return errorMsg();
        return QStringLiteral("%1-kirjautuminen epäonnistui.").arg(federatedProviderName());
    }
}

bool QtFirebaseAuth::running() const
{
    return !m_complete;
}

void QtFirebaseAuth::signOut()
{
    setAction(ActionSignOut);
    qInfo() << "[FIREBASE AUTH] signOut called";
    m_auth->SignOut();
    m_appleAuthorizationCode.clear();
    clearError();
    setToken(QString());
    setComplete(false);
    setSignIn(false);
    setComplete(true);
}

int QtFirebaseAuth::action() const
{
    return m_action;
}

void QtFirebaseAuth::setAction(int action)
{
    if (m_action == action)
        return;
    m_action = action;
    emit actionChanged();
}

int QtFirebaseAuth::errorId() const
{
    return m_errId;
}

QString QtFirebaseAuth::errorMsg() const
{
    return m_errMsg;
}

QString QtFirebaseAuth::email() const
{
    if(signedIn())
    {
        return QString::fromUtf8(m_auth->current_user().email().c_str());
    }
    return QString();
}

QString QtFirebaseAuth::displayName() const
{
    if(signedIn())
    {
        return QString::fromUtf8(m_auth->current_user().display_name().c_str());
    }
    return QString();
}

bool QtFirebaseAuth::emailVerified() const
{
    if(signedIn())
    {
        return m_auth->current_user().is_email_verified();
    }
    return false;
}

QString QtFirebaseAuth::photoUrl() const
{
    if(signedIn())
    {
        return QString::fromUtf8(m_auth->current_user().photo_url().c_str());
    }
    return QString();
}

QString QtFirebaseAuth::uid() const
{
    if(signedIn())
    {
        return QString::fromUtf8(m_auth->current_user().uid().c_str());
    }
    return QString();
}

QString QtFirebaseAuth::phoneNumber() const
{
    if(signedIn())
    {
        return QString::fromUtf8(m_auth->current_user().phone_number().c_str());
    }
    return QString();
}

void QtFirebaseAuth::setComplete(bool complete)
{
    if(m_complete!=complete)
    {
        m_complete = complete;
        qDebug() << "[FIREBASE AUTH] setComplete: running=" << !m_complete << "complete=" << m_complete << "action=" << m_action << "error=" << m_errId;
        emit runningChanged();
        if(m_complete)
        {
            bool success = (m_errId == ErrorNone);
            qDebug() << "[FIREBASE AUTH] setComplete: Emitting completed signal - success=" << success << "action=" << m_action;
            emit completed(success, m_action);
        }
    }
}

void QtFirebaseAuth::setSignIn(bool value)
{
    if(m_signedIn!=value)
    {
        m_signedIn = value;
        emit signedInChanged();
    }
}

void QtFirebaseAuth::init()
{
    if(!qFirebase->ready()) {
        // NOTE using "self" pointer with qDebug() sometimes lead to crashes during life-cycle:
        // init -> terminate -> init -> crash
        qInfo() << "[FIREBASE AUTH] init: base not ready yet";
        return;
    }

    if(!ready() && !initializing()) {
        setInitializing(true);
        m_auth = auth::Auth::GetAuth(qFirebase->firebaseApp());
        qInfo() << "[FIREBASE AUTH] init: native auth initialized";

        if (m_auth && !m_listenersInstalled) {
            m_authStateListener = std::make_unique<AuthStateListenerImpl>(this);
            m_idTokenListener = std::make_unique<IdTokenListenerImpl>(this);
            m_auth->AddAuthStateListener(m_authStateListener.get());
            m_auth->AddIdTokenListener(m_idTokenListener.get());
            m_listenersInstalled = true;
            qInfo() << "[FIREBASE AUTH] init: listeners installed";
        }

        setInitializing(false);
        setReady(true);

        const bool validUser = (m_auth && m_auth->current_user().is_valid());
        qInfo() << "[FIREBASE AUTH] init: current_user valid:" << validUser
                << "uid:" << (validUser ? QString::fromStdString(m_auth->current_user().uid()) : QString())
                << "email:" << (validUser ? maskEmail(QString::fromStdString(m_auth->current_user().email())) : QString());
        setSignIn(validUser);
        if (validUser) {
            qInfo() << "[FIREBASE AUTH] init: session restored, fetching token";
            getToken();
        }
        setComplete(true);
    }
}

void QtFirebaseAuth::onFutureEvent(QString eventId, firebase::FutureBase future)
{
    if(!eventId.startsWith(__QTFIREBASE_ID + QStringLiteral(".auth")))
        return;

    qDebug() << "[FIREBASE AUTH] onFutureEvent:" << eventId << "status:" << future.status() << "error:" << future.error();

    if(future.status() != firebase::kFutureStatusComplete)
    {
        qDebug() << "[FIREBASE AUTH] onFutureEvent: Action not complete. Status:" << future.status() << "Error:" << future.error() << future.error_message();
        setError(ErrorFailure, QStringLiteral("Unknown error"));
    }
    else if(future.error()==auth::kAuthErrorNone)
    {
        clearError();
        if (eventId == __QTFIREBASE_ID + QStringLiteral(".auth.register")) {
            qDebug() << "[FIREBASE AUTH] onFutureEvent: Registration completed successfully";
            if (future.error() == firebase::auth::kAuthErrorNone) {
                const firebase::auth::AuthResult* result = reinterpret_cast<const firebase::auth::AuthResult*>(future.result_void());
                if (result != nullptr) {
                    auth::User user = result->user;
                    qDebug() << "[FIREBASE AUTH] User registered successfully. Email:" << maskEmail(QString::fromStdString(user.email())) << "UID:" << QString::fromStdString(user.uid());
                    qDebug() << "[FIREBASE AUTH] Sending email verification...";
                    qFirebase->addFuture(__QTFIREBASE_ID + QStringLiteral(".auth.sendemailverify"), user.SendEmailVerification());
                    setSignIn(true);
                    qDebug() << "[FIREBASE AUTH] Getting authentication token after registration...";
                    getToken();
                    qDebug() << "[FIREBASE AUTH] Setting signedIn to true, emitting completed signal";
                    setComplete(true);
                } else {
                    qWarning() << "[FIREBASE AUTH] Registration successful but user object is null";
                    setComplete(true);
                }
            } else {
                qWarning() << "[FIREBASE AUTH] Registration failed with error:" << future.error() << future.error_message();
                setComplete(true);
            }
        }
        else if(eventId == __QTFIREBASE_ID + QStringLiteral(".auth.sendemailverify"))
        {
            qDebug() << this << "::onFutureEvent Verification email sent successfully";
        }
        else if (eventId == __QTFIREBASE_ID + QStringLiteral(".auth.deleteUser")) {
            // Parent branch already has future.error() == kAuthErrorNone.
            qInfo() << "[FIREBASE AUTH] onFutureEvent: deleteUser succeeded; Firebase Auth user is deleted for this app.";
            setToken(QString());
            setSignIn(false);
        }
        else if(eventId == __QTFIREBASE_ID + QStringLiteral(".auth.updateProfile"))
        {
            qDebug() << "[FIREBASE AUTH] onFutureEvent: User profile updated successfully";
        }

        else if(eventId == __QTFIREBASE_ID + QStringLiteral(".auth.resetEmail"))
        {
            emit passwordResetEmailSent();
            qDebug() << this << "::onFutureEvent reset email sent successfully";
        }
        else if(eventId == __QTFIREBASE_ID + QStringLiteral(".auth.signin")) {
            qDebug() << "[FIREBASE AUTH] onFutureEvent: Sign in completed";
            if (future.error() == firebase::auth::kAuthErrorNone) {
                const firebase::auth::AuthResult* result = reinterpret_cast<const firebase::auth::AuthResult*>(future.result_void());
                if (result != nullptr) {
                    auth::User user = result->user;
                    qDebug() << "[FIREBASE AUTH] Sign in successful. Email:" << maskEmail(QString::fromStdString(user.email())) << "UID:" << QString::fromStdString(user.uid());
                    setSignIn(true);
                    qDebug() << "[FIREBASE AUTH] Getting authentication token...";
                    getToken();
                    qDebug() << "[FIREBASE AUTH] Setting signedIn to true, emitting completed signal";
                    setComplete(true);
                } else {
                    qWarning() << "[FIREBASE AUTH] Sign in successful but user object is null";
                    setSignIn(false);
                    setComplete(true);
                }
            } else {
                qWarning() << "[FIREBASE AUTH] Sign in failed with error:" << future.error() << future.error_message();
                setSignIn(false);
                setComplete(true);
            }
        }
        else if (isFederatedEvent(__QTFIREBASE_ID, eventId)) {
            const firebase::auth::AuthResult *result =
                reinterpret_cast<const firebase::auth::AuthResult *>(future.result_void());
            if (future.error() == firebase::auth::kAuthErrorNone && result != nullptr && result->user.is_valid()) {
                qInfo() << "[FIREBASE AUTH] Federated auth operation succeeded for event:" << eventId;
                handleFederatedSuccess(eventId);
            } else {
                qWarning() << "[FIREBASE AUTH] Federated auth operation failed:" << future.error()
                           << future.error_message();
                handleFederatedFailure(eventId, future.error());
            }
        }
        else if (eventId == __QTFIREBASE_ID + QStringLiteral(".auth.fetchproviders")) {
            const auth::Auth::FetchProvidersResult *result =
                reinterpret_cast<const auth::Auth::FetchProvidersResult *>(future.result_void());
            QStringList methods;
            if (result != nullptr) {
                for (const std::string &provider : result->providers)
                    methods.append(QString::fromStdString(provider));
            }
            emit signInMethodsFetched(methods);
        }
    }
    else
    {
        if(eventId == __QTFIREBASE_ID + QStringLiteral(".auth.register"))
        {
            qDebug() << "[FIREBASE AUTH] onFutureEvent: Registering user completed with error:" << future.error() << future.error_message();
            setError(ErrorFailure, QString::fromStdString(future.error_message()));
            setComplete(true);
        }
        else if(eventId == __QTFIREBASE_ID + QStringLiteral(".auth.sendemailverify"))
        {
            qDebug() << "[FIREBASE AUTH] onFutureEvent: Verification email send error:" << future.error() << future.error_message();
        }
        else if(eventId == __QTFIREBASE_ID + QStringLiteral(".auth.signin"))
        {
            qDebug() << "[FIREBASE AUTH] onFutureEvent: Sign in error:" << future.error() << future.error_message();
            setSignIn(false);
            setError(ErrorFailure, QString::fromStdString(future.error_message()));
            setComplete(true);
        }
        else if (isFederatedEvent(__QTFIREBASE_ID, eventId)) {
            qWarning() << "[FIREBASE AUTH] onFutureEvent: federated auth error:" << future.error()
                       << future.error_message();
            handleFederatedFailure(eventId, future.error());
        }
        else if (eventId == __QTFIREBASE_ID + QStringLiteral(".auth.fetchproviders")) {
            qWarning() << "[FIREBASE AUTH] onFutureEvent: fetch providers error:" << future.error()
                       << future.error_message();
            emit signInMethodsFetched(QStringList());
            setError(future.error(), localizedErrorMessage(future.error()));
        }
        else if(eventId == __QTFIREBASE_ID + QStringLiteral(".auth.resetEmail"))
        {
            qDebug() << this << "::onFutureEvent reset email error" << future.error() << future.error_message();
        }
        else if(eventId == __QTFIREBASE_ID + QStringLiteral(".auth.deleteUser"))
        {
            qWarning() << "[FIREBASE AUTH] onFutureEvent: deleteUser failed"
                       << future.error() << future.error_message()
                       << "(Firebase may require recent login for this sensitive operation)";
        }
        else if(eventId == __QTFIREBASE_ID + QStringLiteral(".auth.updateProfile"))
        {
            qDebug() << "[FIREBASE AUTH] onFutureEvent: User profile update error:" << future.error() << future.error_message();
        }
        setError(future.error(), QString::fromUtf8(future.error_message()));
    }
    setComplete(true);
}

void QtFirebaseAuth::handleFederatedSuccess(const QString &eventId)
{
    if (isAppleEvent(eventId)) {
        applyAppleFullNameIfMissing();
        m_pendingAppleIdToken.clear();
        m_pendingAppleEmail.clear();
    } else {
        m_pendingGoogleIdToken.clear();
    }
    setSignIn(true);
    getToken();
}

void QtFirebaseAuth::handleFederatedFailure(const QString &eventId, int error)
{
    if (error == auth::kAuthErrorAccountExistsWithDifferentCredentials && isFederatedSignInEvent(__QTFIREBASE_ID, eventId)) {
        QString email;
        if (isAppleEvent(eventId)) {
            // Apple sends the email only on first authorization; the identity token
            // carries it (possibly a privaterelay.appleid.com address) on later ones.
            email = m_pendingAppleEmail.isEmpty() ? emailFromIdToken(m_pendingAppleIdToken) : m_pendingAppleEmail;
        } else {
            email = emailFromIdToken(m_pendingGoogleIdToken);
        }
        emit accountLinkRequired(email, QStringList());
    }
    if (isAppleEvent(eventId)) {
        m_pendingAppleIdToken.clear();
        m_pendingAppleEmail.clear();
        m_pendingAppleFullName.clear();
    }
    setSignIn(isFederatedReauthEvent(__QTFIREBASE_ID, eventId) && signedIn());
    setError(error, localizedErrorMessage(error));
}

QString QtFirebaseAuth::token() const
{
    return m_token;
}

void QtFirebaseAuth::setToken(const QString &newToken)
{
    if (m_token == newToken)
        return;
    m_token = newToken;
    qInfo() << "[FIREBASE AUTH] setToken: Token updated (length:" << newToken.length() << "), emitting tokenChanged";
    emit tokenChanged();
}

void QtFirebaseAuth::refreshToken()
{
    qInfo() << "[FIREBASE AUTH] refreshToken: forcing fresh ID token";
    getToken(true);
}

void QtFirebaseAuth::getToken(bool forceRefresh) {
    if (m_auth && m_auth->current_user().is_valid()) {
        const QString email = QString::fromStdString(m_auth->current_user().email());
        const QString uid = QString::fromStdString(m_auth->current_user().uid());
        qInfo() << "[FIREBASE AUTH] getToken: requesting token" << "uid:" << uid << "email:" << maskEmail(email) << "forceRefresh:" << forceRefresh;
        m_auth->current_user().GetToken(forceRefresh).OnCompletion([this, uid](const firebase::Future<std::string>& result) {
            if (result.status() == firebase::kFutureStatusComplete) {
                if (result.error() == firebase::auth::kAuthErrorNone) {
                    if (!m_auth || !m_auth->current_user().is_valid() ||
                        QString::fromStdString(m_auth->current_user().uid()) != uid) {
                        qInfo() << "[FIREBASE AUTH] getToken: ignoring token for stale signed-in user";
                        return;
                    }
                    std::string idToken = *result.result();
                    QString tokenStr = QString::fromStdString(idToken);
                    qInfo() << "[FIREBASE AUTH] getToken: token received (len:" << tokenStr.length() << ")";
                    setToken(tokenStr);
                } else {
                    qWarning() << "[FIREBASE AUTH] getToken: Error retrieving token:" << result.error() << result.error_message();
                }
            } else {
                qWarning() << "[FIREBASE AUTH] getToken: Token retrieval incomplete or failed. Status:" << result.status();
            }
        });
    } else {
        qWarning() << "[FIREBASE AUTH] getToken: Cannot retrieve token - No user signed in.";
    }
}

void QtFirebaseAuth::addAuthStateListener(firebase::auth::AuthStateListener* listener)
{
    if (m_auth) {
        m_auth->AddAuthStateListener(listener);
    }
}

void QtFirebaseAuth::removeAuthStateListener(firebase::auth::AuthStateListener* listener)
{
    if (m_auth) {
        m_auth->RemoveAuthStateListener(listener);
    }
}



void QtFirebaseAuth::addIdTokenListener(firebase::auth::IdTokenListener* listener)
{
    if (m_auth) {
        m_auth->AddIdTokenListener(listener);
    }
}

void QtFirebaseAuth::removeIdTokenListener(firebase::auth::IdTokenListener* listener)
{
    if (m_auth) {
        m_auth->RemoveIdTokenListener(listener);
    }
}

void QtFirebaseAuth::onIdTokenChanged()
{
    if (m_auth && m_auth->current_user().is_valid()) {
        qInfo() << "[FIREBASE AUTH] onIdTokenChanged: user valid, refreshing token";
        getToken();
        qInfo() << "[FIREBASE AUTH] onIdTokenChanged: email:" << maskEmail(QString::fromStdString(m_auth->current_user().email()));
    } else {
        qInfo() << "[FIREBASE AUTH] onIdTokenChanged: no user signed in";
    }
}


void QtFirebaseAuth::onAuthStateChanged()
{
    if (m_auth && m_auth->current_user().is_valid()) {
        setSignIn(true);
        qInfo() << "[FIREBASE AUTH] onAuthStateChanged: signed in:" << maskEmail(QString::fromStdString(m_auth->current_user().email()))
                << "uid:" << QString::fromStdString(m_auth->current_user().uid());
    } else {
        setSignIn(false);
        qInfo() << "[FIREBASE AUTH] onAuthStateChanged: signed out";
    }
}

void QtFirebaseAuth::updateUserProfile(const QString& displayName, const QString& phoneNumber)
{
    if (!signedIn()) {
        qWarning() << "[FIREBASE AUTH] updateUserProfile: Cannot update profile - no user signed in";
        return;
    }
    
    if (running()) {
        qWarning() << "[FIREBASE AUTH] updateUserProfile: Already running, ignoring request";
        return;
    }
    
    qDebug() << "[FIREBASE AUTH] updateUserProfile called - displayName:" << displayName << "phoneNumber:" << phoneNumber;
    
    // Note: Phone number cannot be set via UserProfile update in Firebase Auth.
    // Phone numbers are only set through phone authentication flow.
    // The phone number parameter is kept for API consistency, but we only update displayName.
    // Phone number should be stored in Firestore instead.
    
    setAction(ActionUpdateProfile);
    clearError();
    setComplete(false);
    
    auth::User user = m_auth->current_user();
    auth::User::UserProfile profile;
    
    if (!displayName.isEmpty()) {
        profile.display_name = displayName.toUtf8().constData();
    }
    
    // Phone number cannot be updated via UserProfile - it requires phone authentication
    // We'll store it in Firestore instead (which is already done in createEmployee)
    if (!phoneNumber.isEmpty()) {
        qDebug() << "[FIREBASE AUTH] updateUserProfile: Phone number provided but cannot be set via UserProfile. It will be stored in Firestore.";
    }
    
    firebase::Future<void> future = user.UpdateUserProfile(profile);
    qFirebase->addFuture(__QTFIREBASE_ID + QStringLiteral(".auth.updateProfile"), future);
    qDebug() << "[FIREBASE AUTH] updateUserProfile: Future added, waiting for result";
}


