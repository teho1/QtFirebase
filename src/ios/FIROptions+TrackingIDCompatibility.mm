#import "FIROptions+TrackingIDCompatibility.h"
#import <FirebaseCore/FirebaseCore.h>

@implementation FIROptions (TrackingIDCompatibility)

- (NSString *)trackingID {
    return nil;
}

@end
