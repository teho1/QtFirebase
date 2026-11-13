#include "../qtfirebaseapplesignin.h"

#include "../qtfirebaseapplenonce.h"
#include "../qtfirebaseauth.h"

#import <AuthenticationServices/AuthenticationServices.h>
#import <UIKit/UIKit.h>

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

} // namespace QtFirebaseAppleSignIn
