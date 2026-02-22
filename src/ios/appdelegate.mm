#import "UIKit/UIKit.h"
#include <QtCore>

#import "FIROptions+TrackingIDCompatibility.h"
#import "Firebase/Firebase.h"
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

    // Request notification permissions (required for FCM token registration)
    UNUserNotificationCenter *center = [UNUserNotificationCenter currentNotificationCenter];
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
                          }];

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
