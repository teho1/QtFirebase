#include "../qtfirebaseapplesignin.h"

#include "../qtfirebaseapplenonce.h"
#include "../qtfirebaseauth.h"
#include "../qtfirebaseauthhelpers.h"

#import <AuthenticationServices/AuthenticationServices.h>
#import <UIKit/UIKit.h>
#import <objc/message.h>

#include <QMetaObject>

// The app target does not enable ARC; balance +1 allocations so this file is correct either way.
#if __has_feature(objc_arc)
#define QTFIREBASE_AUTORELEASE(x) (x)
#else
#define QTFIREBASE_AUTORELEASE(x) [(x) autorelease]
#endif

namespace QtFirebaseAppleSignIn {
namespace {

QtFirebaseAuth *g_pendingAuth = nullptr;
AppleSignInCallback g_pendingCallback;
QString g_pendingRawNonce;

UIWindow *keyWindow()
{
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (scene.activationState != UISceneActivationStateForegroundActive
            || ![scene isKindOfClass:[UIWindowScene class]]) {
            continue;
        }
        for (UIWindow *window in ((UIWindowScene *)scene).windows) {
            if (window.isKeyWindow)
                return window;
        }
    }
    return nil;
}

void deliver(const Result &result)
{
    QtFirebaseAuth *auth = g_pendingAuth;
    AppleSignInCallback callback = g_pendingCallback;
    g_pendingAuth = nullptr;
    g_pendingCallback = nullptr;
    g_pendingRawNonce.clear();

    if (!auth || !callback)
        return;

    QMetaObject::invokeMethod(auth, [callback, result]() {
        callback(result);
    }, Qt::QueuedConnection);
}

void deliverImmediately(QtFirebaseAuth *auth, const AppleSignInCallback &callback,
                        const QString &errorMessage)
{
    if (!auth || !callback)
        return;
    QMetaObject::invokeMethod(auth, [callback, errorMessage]() {
        Result result;
        result.errorMessage = errorMessage;
        callback(result);
    }, Qt::QueuedConnection);
}

id firAuthInstance()
{
    // FIRAuth is the Firebase iOS SDK object the C++ SDK wraps; its Swift
    // header is not importable from this target, so call it via the runtime.
    Class authClass = NSClassFromString(@"FIRAuth");
    SEL authSelector = NSSelectorFromString(@"auth");
    return (authClass && [authClass respondsToSelector:authSelector])
        ? ((id (*)(id, SEL))objc_msgSend)(authClass, authSelector)
        : nil;
}

int authErrorFromNSError(NSError *error)
{
    if (![error.domain isEqualToString:@"FIRAuthErrorDomain"])
        return ::firebase::auth::kAuthErrorFailure;
    return QtFirebaseAuthHelpers::authErrorFromFirAuthErrorCode(error.code);
}

} // namespace
} // namespace QtFirebaseAppleSignIn

@interface QtFirebaseAppleSignInDelegate
    : NSObject <ASAuthorizationControllerDelegate, ASAuthorizationControllerPresentationContextProviding>
@property (nonatomic, strong) ASAuthorizationController *controller;
@end

@implementation QtFirebaseAppleSignInDelegate

- (ASPresentationAnchor)presentationAnchorForAuthorizationController:(ASAuthorizationController *)controller
{
    Q_UNUSED(controller)
    return QtFirebaseAppleSignIn::keyWindow();
}

- (void)authorizationController:(ASAuthorizationController *)controller
    didCompleteWithAuthorization:(ASAuthorization *)authorization
{
    Q_UNUSED(controller)
    using namespace QtFirebaseAppleSignIn;

    Result result;
    if (![authorization.credential isKindOfClass:[ASAuthorizationAppleIDCredential class]]) {
        result.errorMessage = QStringLiteral("Sign in with Apple returned an unexpected credential.");
        deliver(result);
        self.controller = nil;
        return;
    }

    ASAuthorizationAppleIDCredential *credential = (ASAuthorizationAppleIDCredential *)authorization.credential;
    NSData *tokenData = credential.identityToken;
    NSString *idToken = tokenData ? QTFIREBASE_AUTORELEASE([[NSString alloc] initWithData:tokenData encoding:NSUTF8StringEncoding]) : nil;
    if (idToken.length == 0) {
        result.errorMessage = QStringLiteral("Sign in with Apple did not return an identity token.");
        deliver(result);
        self.controller = nil;
        return;
    }

    result.success = true;
    result.idToken = QString::fromNSString(idToken);
    result.rawNonce = g_pendingRawNonce;
    if (credential.email)
        result.email = QString::fromNSString(credential.email);
    if (credential.authorizationCode) {
        NSString *code = QTFIREBASE_AUTORELEASE([[NSString alloc] initWithData:credential.authorizationCode
                                                                       encoding:NSUTF8StringEncoding]);
        if (code)
            result.authorizationCode = QString::fromNSString(code);
    }
    if (credential.fullName) {
        NSString *name = [NSPersonNameComponentsFormatter
            localizedStringFromPersonNameComponents:credential.fullName
                                              style:NSPersonNameComponentsFormatterStyleDefault
                                            options:0];
        if (name)
            result.fullName = QString::fromNSString(name).trimmed();
    }
    deliver(result);
    self.controller = nil;
}

- (void)authorizationController:(ASAuthorizationController *)controller
           didCompleteWithError:(NSError *)error
{
    Q_UNUSED(controller)
    using namespace QtFirebaseAppleSignIn;

    Result result;
    result.cancelled = error.code == ASAuthorizationErrorCanceled;
    result.errorMessage = error.localizedDescription
        ? QString::fromNSString(error.localizedDescription)
        : QStringLiteral("Sign in with Apple failed.");
    deliver(result);
    self.controller = nil;
}

@end

namespace QtFirebaseAppleSignIn {

namespace {
QtFirebaseAppleSignInDelegate *g_delegate = nil;
}

bool isAvailable()
{
    return true;
}

void requestSignIn(QtFirebaseAuth *auth, AppleSignInCallback callback)
{
    if (g_pendingCallback) {
        deliverImmediately(auth, callback, QStringLiteral("Sign in with Apple is already in progress."));
        return;
    }
    if (!keyWindow()) {
        deliverImmediately(auth, callback, QStringLiteral("Could not find a window for Sign in with Apple."));
        return;
    }

    const QString rawNonce = QtFirebaseAppleNonce::generateRawNonce();
    if (rawNonce.isEmpty()) {
        deliverImmediately(auth, callback, QStringLiteral("Could not generate a nonce for Sign in with Apple."));
        return;
    }

    g_pendingAuth = auth;
    g_pendingCallback = std::move(callback);
    g_pendingRawNonce = rawNonce;

    ASAuthorizationAppleIDProvider *provider = QTFIREBASE_AUTORELEASE([[ASAuthorizationAppleIDProvider alloc] init]);
    ASAuthorizationAppleIDRequest *request = [provider createRequest];
    request.requestedScopes = @[ASAuthorizationScopeFullName, ASAuthorizationScopeEmail];
    request.nonce = QtFirebaseAppleNonce::sha256Hex(rawNonce).toNSString();

    if (!g_delegate)
        g_delegate = [[QtFirebaseAppleSignInDelegate alloc] init];

    ASAuthorizationController *controller = QTFIREBASE_AUTORELEASE(
        [[ASAuthorizationController alloc] initWithAuthorizationRequests:@[request]]);
    controller.delegate = g_delegate;
    controller.presentationContextProvider = g_delegate;
    // ASAuthorizationController holds its delegate weakly; keep the controller alive until it finishes.
    g_delegate.controller = controller;
    [controller performRequests];
}

void authenticateWithFirebase(QtFirebaseAuth *auth, FirebaseOperation operation,
                              const QString &idToken, const QString &rawNonce,
                              FirebaseCallback callback)
{
    if (!auth || !callback)
        return;

    auto deliverAuth = [auth, callback](int authError, const QString &errorMessage) {
        QMetaObject::invokeMethod(auth, [callback, authError, errorMessage]() {
            callback(authError, errorMessage);
        }, Qt::QueuedConnection);
    };

    Class providerClass = NSClassFromString(@"FIROAuthProvider");
    SEL appleSelector = NSSelectorFromString(@"appleCredentialWithIDToken:rawNonce:fullName:");
    SEL oidcSelector = NSSelectorFromString(@"credentialWithProviderID:IDToken:rawNonce:");
    id credential = nil;
    if (providerClass && [providerClass respondsToSelector:appleSelector]) {
        credential = ((id (*)(id, SEL, NSString *, NSString *, NSPersonNameComponents *))objc_msgSend)(
            providerClass, appleSelector, idToken.toNSString(), rawNonce.toNSString(), nil);
    } else if (providerClass && [providerClass respondsToSelector:oidcSelector]) {
        credential = ((id (*)(id, SEL, NSString *, NSString *, NSString *))objc_msgSend)(
            providerClass, oidcSelector, @"apple.com", idToken.toNSString(), rawNonce.toNSString());
    }
    if (!credential) {
        deliverAuth(::firebase::auth::kAuthErrorInvalidCredential,
                    QStringLiteral("FIROAuthProvider Apple credential is not available."));
        return;
    }

    id target = firAuthInstance();
    SEL selector = NSSelectorFromString(@"signInWithCredential:completion:");
    if (operation != FirebaseOperation::SignIn) {
        target = target ? ((id (*)(id, SEL))objc_msgSend)(target, NSSelectorFromString(@"currentUser")) : nil;
        selector = NSSelectorFromString(operation == FirebaseOperation::Link
            ? @"linkWithCredential:completion:"
            : @"reauthenticateWithCredential:completion:");
    }
    if (!target || ![target respondsToSelector:selector]) {
        deliverAuth(::firebase::auth::kAuthErrorFailure,
                    operation == FirebaseOperation::SignIn
                        ? QStringLiteral("FIRAuth is not available.")
                        : QStringLiteral("No signed-in Firebase user."));
        return;
    }

    void (^completion)(id, NSError *) = ^(id authResult, NSError *error) {
        Q_UNUSED(authResult)
        if (error) {
            deliverAuth(authErrorFromNSError(error), error.localizedDescription
                ? QString::fromNSString(error.localizedDescription)
                : QStringLiteral("Sign in with Apple failed."));
            return;
        }
        deliverAuth(::firebase::auth::kAuthErrorNone, QString());
    };
    ((void (*)(id, SEL, id, void (^)(id, NSError *)))objc_msgSend)(target, selector, credential, completion);
}

void revokeToken(QtFirebaseAuth *auth, const QString &authorizationCode, RevokeCallback callback)
{
    if (!auth || !callback)
        return;

    auto deliverRevoke = [auth, callback](bool success, const QString &errorMessage) {
        QMetaObject::invokeMethod(auth, [callback, success, errorMessage]() {
            callback(success, errorMessage);
        }, Qt::QueuedConnection);
    };

    SEL revokeSelector = NSSelectorFromString(@"revokeTokenWithAuthorizationCode:completion:");
    id firAuth = firAuthInstance();
    if (!firAuth || ![firAuth respondsToSelector:revokeSelector]) {
        deliverRevoke(false, QStringLiteral("FIRAuth revokeTokenWithAuthorizationCode is not available."));
        return;
    }

    void (^completion)(NSError *) = ^(NSError *error) {
        if (error) {
            deliverRevoke(false, error.localizedDescription
                ? QString::fromNSString(error.localizedDescription)
                : QStringLiteral("Apple token revocation failed."));
            return;
        }
        deliverRevoke(true, QString());
    };
    ((void (*)(id, SEL, NSString *, void (^)(NSError *)))objc_msgSend)(
        firAuth, revokeSelector, authorizationCode.toNSString(), completion);
}

} // namespace QtFirebaseAppleSignIn
