#include "../qtfirebasegooglesignin.h"

#include "../qtfirebaseauth.h"

#import <GoogleSignIn/GoogleSignIn.h>
#import <UIKit/UIKit.h>

#include <QGuiApplication>
#include <QMetaObject>
#include <QUrl>

namespace QtFirebaseGoogleSignIn {

namespace {

GoogleSignInCallback g_pendingCallback;
QtFirebaseAuth *g_pendingAuth = nullptr;

UIViewController *topViewController()
{
    UIWindow *keyWindow = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if (scene.activationState != UISceneActivationStateForegroundActive
            || ![scene isKindOfClass:[UIWindowScene class]]) {
            continue;
        }
        UIWindowScene *windowScene = (UIWindowScene *)scene;
        for (UIWindow *window in windowScene.windows) {
            if (window.isKeyWindow) {
                keyWindow = window;
                break;
            }
        }
        if (keyWindow)
            break;
    }
    if (!keyWindow)
        return nil;

    UIViewController *controller = keyWindow.rootViewController;
    while (controller.presentedViewController)
        controller = controller.presentedViewController;
    return controller;
}

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

void configureGoogleSignInIfNeeded()
{
    static bool configured = false;
    if (configured)
        return;

    NSString *plistPath = [[NSBundle mainBundle] pathForResource:@"GoogleService-Info" ofType:@"plist"];
    NSDictionary *plist = plistPath ? [NSDictionary dictionaryWithContentsOfFile:plistPath] : nil;
    NSString *clientId = plist[@"CLIENT_ID"];
    if (!clientId) {
        NSLog(@"GoogleSignIn: GoogleService-Info.plist CLIENT_ID missing");
        return;
    }

    GIDConfiguration *configuration = [[GIDConfiguration alloc] initWithClientID:clientId];
    [GIDSignIn.sharedInstance setConfiguration:configuration];
    configured = true;
}

} // namespace

void requestSignIn(QtFirebaseAuth *auth, GoogleSignInCallback callback)
{
    if (g_pendingCallback) {
        if (callback) {
            QMetaObject::invokeMethod(auth, [callback]() {
                callback(false, QString(), QString(),
                         QStringLiteral("Google Sign-In is already in progress."));
            }, Qt::QueuedConnection);
        }
        return;
    }

    configureGoogleSignInIfNeeded();

    UIViewController *presentingController = topViewController();
    if (!presentingController) {
        if (callback) {
            QMetaObject::invokeMethod(auth, [callback]() {
                callback(false, QString(), QString(),
                         QStringLiteral("Could not find a view controller for Google Sign-In."));
            }, Qt::QueuedConnection);
        }
        return;
    }

    g_pendingAuth = auth;
    g_pendingCallback = std::move(callback);

    [GIDSignIn.sharedInstance signInWithPresentingViewController:presentingController
                                                        completion:^(GIDSignInResult *result, NSError *error) {
        if (error) {
            const QString message = error.localizedDescription
                ? QString::fromNSString(error.localizedDescription)
                : QStringLiteral("Google Sign-In failed.");
            deliverOnAuthThread(false, QString(), QString(), message);
            return;
        }

        NSString *idToken = result.user.idToken.tokenString;
        if (!idToken || idToken.length == 0) {
            deliverOnAuthThread(false, QString(), QString(),
                                QStringLiteral("Google Sign-In did not return an ID token."));
            return;
        }

        deliverOnAuthThread(true, QString::fromNSString(idToken), QString(), QString());
    }];
}

bool handleOpenUrl(const QUrl &url)
{
    configureGoogleSignInIfNeeded();
    NSURL *nsUrl = [NSURL URLWithString:url.toString().toNSString()];
    if (!nsUrl)
        return false;
    return [GIDSignIn.sharedInstance handleURL:nsUrl];
}

} // namespace QtFirebaseGoogleSignIn
