#import "UIKit/UIKit.h"
#include <QtCore>

// Fix for Qt iOS crash: -[UIImage undo]: unrecognized selector
// iOS's shake-to-undo / three-finger-swipe gesture sends `undo:` and `redo:`
// up the UIResponder chain. In Qt Quick apps a UIImage can end up in that
// chain and, because UIImage doesn't implement those selectors, the runtime
// throws an NSInvalidArgumentException.  Adding no-op implementations via a
// category makes UIImage silently absorb the message instead of crashing.
@interface UIImage (QtUndoFix)
- (void)undo:(id)sender;
- (void)redo:(id)sender;
@end

@implementation UIImage (QtUndoFix)
- (void)undo:(id)sender { (void)sender; }
- (void)redo:(id)sender { (void)sender; }
@end

// CMake does not currently propagate the Firebase xcframework header search paths
// to this Objective-C++ compilation unit the same way qmake does, so include the
// vendored framework headers directly for now.
#import "../../../../../extensions/ios/Firebase/FirebaseAnalytics/FirebaseCore.xcframework/ios-arm64/FirebaseCore.framework/Headers/FirebaseCore.h"
#import "../../../../../extensions/ios/Firebase/FirebaseMessaging/FirebaseMessaging.xcframework/ios-arm64/FirebaseMessaging.framework/Headers/FirebaseMessaging.h"
#import <UserNotifications/UserNotifications.h>

@interface QIOSApplicationDelegate : UIResponder <UIApplicationDelegate, UNUserNotificationCenterDelegate>
@end

@interface QIOSApplicationDelegate(AppDelegate)
@end

@implementation QIOSApplicationDelegate (AppDelegate)

- (BOOL)application:(UIApplication *)application
  didFinishLaunchingWithOptions:(NSDictionary *)launchOptions
{
    Q_UNUSED(application);
    Q_UNUSED(launchOptions);

    // Use Firebase library to configure APIs
    NSLog(@"Call FIRApp configure");
    [FIRApp configure];

    // Request notification permissions
 /*   UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
    center.delegate = self; // Set UNUserNotificationCenter delegate
    [center requestAuthorizationWithOptions:(UNAuthorizationOptionAlert | UNAuthorizationOptionBadge | UNAuthorizationOptionSound)
                          completionHandler:^(BOOL granted, NSError * _Nullable error) {
                              if (error) {
                                  NSLog(@"Error requesting notification permissions: %@", error);
                              }
                              if (granted) {
                                  NSLog(@"Notification permissions granted");
                                  dispatch_async(dispatch_get_main_queue(), ^{
                                      [[UIApplication sharedApplication] registerForRemoteNotifications];
                                  });
                              } else {
                                  NSLog(@"Notification permissions denied");
                              }
                          }];*/

    return YES;
}

- (void)application:(UIApplication *)application didRegisterForRemoteNotificationsWithDeviceToken:(NSData *)deviceToken {
    // Pass the token to Firebase Messaging
   [FIRMessaging messaging].APNSToken = deviceToken;
}

- (void)application:(UIApplication *)application didFailToRegisterForRemoteNotificationsWithError:(NSError *)error {
    NSLog(@"Failed to register for remote notifications: %@", error);
}

- (void)applicationDidBecomeActive:(UIApplication *)application {
    Q_UNUSED(application);
    UIApplication.sharedApplication.applicationIconBadgeNumber = 0;
}

// UNUserNotificationCenterDelegate methods
- (void)userNotificationCenter:(UNUserNotificationCenter *)center
       willPresentNotification:(UNNotification *)notification
         withCompletionHandler:(void (^)(UNNotificationPresentationOptions options))completionHandler {
    NSLog(@"Foreground notification received: %@", notification.request.content.userInfo);

    // Handle the notification and decide how it should be presented
    completionHandler(UNNotificationPresentationOptionAlert | UNNotificationPresentationOptionSound);
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center
didReceiveNotificationResponse:(UNNotificationResponse *)response
         withCompletionHandler:(void (^)(void))completionHandler {
    NSLog(@"Notification clicked: %@", response.notification.request.content.userInfo);

    // Handle user interaction with the notification
    completionHandler();
}

@end
