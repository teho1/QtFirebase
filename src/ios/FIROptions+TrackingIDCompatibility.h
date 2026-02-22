#import <Foundation/Foundation.h>
#import <FirebaseCore/FirebaseCore.h>

/**
 * Compatibility category for Firebase C++ SDK which expects the deprecated
 * trackingID property. New Firebase iOS SDK removed it - we provide a stub
 * returning nil so the C++ SDK doesn't crash.
 */
@interface FIROptions (TrackingIDCompatibility)
@property (nonatomic, copy, nullable, readonly) NSString *trackingID;
@end
