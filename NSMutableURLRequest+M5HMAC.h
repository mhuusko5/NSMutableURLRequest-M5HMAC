//
//  NSMutableURLRequest+M5HMAC.h
//  NSMutableURLRequest+M5HMAC
//

#import <Foundation/Foundation.h>

@interface NSMutableURLRequest (M5HMAC)

#pragma mark - NSMutableURLRequest+M5HMAC -

#pragma mark Methods

- (void)M5_HMACSignWithID:(NSString *)ID secret:(NSString *)secret;

#pragma mark -

@end
