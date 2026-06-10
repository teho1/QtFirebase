#include "qtfirebaseauth.h"

namespace auth = ::firebase::auth;

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
    qInfo() << "[FIREBASE AUTH] registerUser called for email:" << email;
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

    qInfo() << "[FIREBASE AUTH] deleteUser: deleting current Firebase Auth user"
            << "uid:" << QString::fromStdString(m_auth->current_user().uid())
            << "email:" << QString::fromStdString(m_auth->current_user().email());
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
    qInfo() << "[FIREBASE AUTH] signIn called for email:" << email;
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

bool QtFirebaseAuth::running() const
{
    return !m_complete;
}

void QtFirebaseAuth::signOut()
{
    setAction(ActionSignOut);
    qInfo() << "[FIREBASE AUTH] signOut called";
    m_auth->SignOut();
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
                << "email:" << (validUser ? QString::fromStdString(m_auth->current_user().email()) : QString());
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
                    qDebug() << "[FIREBASE AUTH] User registered successfully. Email:" << QString::fromStdString(user.email()) << "UID:" << QString::fromStdString(user.uid());
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
        if (eventId == __QTFIREBASE_ID + QStringLiteral(".auth.signin")) {
            qDebug() << "[FIREBASE AUTH] onFutureEvent: Sign in completed";
            if (future.error() == firebase::auth::kAuthErrorNone) {
                const firebase::auth::AuthResult* result = reinterpret_cast<const firebase::auth::AuthResult*>(future.result_void());
                if (result != nullptr) {
                    auth::User user = result->user;
                    qDebug() << "[FIREBASE AUTH] Sign in successful. Email:" << QString::fromStdString(user.email()) << "UID:" << QString::fromStdString(user.uid());
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

void QtFirebaseAuth::getToken() {
    if (m_auth && m_auth->current_user().is_valid()) {
        const QString email = QString::fromStdString(m_auth->current_user().email());
        const QString uid = QString::fromStdString(m_auth->current_user().uid());
        qInfo() << "[FIREBASE AUTH] getToken: requesting token" << "uid:" << uid << "email:" << email;
        m_auth->current_user().GetToken(false).OnCompletion([this, uid](const firebase::Future<std::string>& result) {
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
        qInfo() << "[FIREBASE AUTH] onIdTokenChanged: email:" << QString::fromStdString(m_auth->current_user().email());
    } else {
        qInfo() << "[FIREBASE AUTH] onIdTokenChanged: no user signed in";
    }
}


void QtFirebaseAuth::onAuthStateChanged()
{
    if (m_auth && m_auth->current_user().is_valid()) {
        setSignIn(true);
        qInfo() << "[FIREBASE AUTH] onAuthStateChanged: signed in:" << QString::fromStdString(m_auth->current_user().email())
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


