//
//  NSMutableURLRequest+M5HMAC.m
//  NSMutableURLRequest+M5HMAC
//

#import "NSMutableURLRequest+M5HMACInternal.h"

#import <CommonCrypto/CommonDigest.h>
#import <CommonCrypto/CommonHMAC.h>

static char base64EncodingTable[64] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', '+', '/'
};

@implementation NSString (M5Crypto)

#pragma mark - NSString+M5Crypto (Private) -

#pragma mark Methods

- (NSString *)M5_SHA1WithSecret:(NSString *)secret {
    const char *cKey = [secret cStringUsingEncoding:NSUTF8StringEncoding];
    const char *cData = [self cStringUsingEncoding:NSUTF8StringEncoding];
    
    unsigned char cHMAC[CC_SHA1_DIGEST_LENGTH];
    
    CCHmac(kCCHmacAlgSHA1, cKey, strlen(cKey), cData, strlen(cData), cHMAC);
    
    NSData *HMAC = [[NSData alloc] initWithBytes:cHMAC length:sizeof(cHMAC)];
    
    NSString *hash = [HMAC base64EncodedStringWithOptions:NSDataBase64EncodingEndLineWithLineFeed];
    
    return hash;
}

- (NSString *)M5_base64StringFromData:(NSData *)data length:(int)length {
    unsigned long ixtext, lentext;
    long ctremaining;
    unsigned char input[3], output[4];
    short i, charsonline = 0, ctcopy;
    const unsigned char *raw;
    NSMutableString *result;
    
    lentext = data.length;
    if (lentext < 1) {
        return @"";
    }
    
    result = [NSMutableString stringWithCapacity:lentext];
    raw = data.bytes;
    ixtext = 0;
    
    while (true) {
        ctremaining = lentext - ixtext;
        if (ctremaining <= 0) {
            break;
        }
        
        for (i = 0; i < 3; i++) {
            unsigned long ix = ixtext + i;
            if (ix < lentext) {
                input[i] = raw[ix];
            } else {
                input[i] = 0;
            }
        }
        
        output[0] = (input[0] & 0xFC) >> 2;
        output[1] = ((input[0] & 0x03) << 4) | ((input[1] & 0xF0) >> 4);
        output[2] = ((input[1] & 0x0F) << 2) | ((input[2] & 0xC0) >> 6);
        output[3] = input[2] & 0x3F;
        ctcopy = 4;
        
        switch (ctremaining) {
            case 1:
                ctcopy = 2;
                break;
            case 2:
                ctcopy = 3;
                break;
        }
        
        for (i = 0; i < ctcopy; i++) {
            [result appendString:[NSString stringWithFormat:@"%c", base64EncodingTable[output[i]]]];
        }
        
        for (i = ctcopy; i < 4; i++) {
            [result appendString:@"="];
        }
        
        ixtext += 3;
        charsonline += 4;
        
        if ((length > 0) && (charsonline >= length)) {
            charsonline = 0;
        }
    }
    
    return result;
}

#pragma mark Properties

- (NSString *)M5_base64MD5 {
    const char *ptr = self.UTF8String;
    unsigned char md5Buffer[CC_MD5_DIGEST_LENGTH];
    
    CC_MD5(ptr, (CC_LONG)strlen(ptr), md5Buffer);
    
    NSData *data = [NSData dataWithBytes:md5Buffer length:CC_MD5_DIGEST_LENGTH];
    NSString *base64String = [self M5_base64StringFromData:data length:CC_MD5_DIGEST_LENGTH];
    
    return base64String;
}

@end

@implementation NSDate (M5HTTP)

#pragma mark - NSDate+M5HTTP (Private) -

#pragma mark Properties

+ (NSString *)M5_HTTPDateString {
    NSDateFormatter *formatter = NSDateFormatter.new;
    
    formatter.dateFormat = @"EEE, dd MMM yyyy HH:mm:ss z";
    formatter.timeZone = [NSTimeZone timeZoneWithAbbreviation:@"GMT"];
    formatter.locale = [NSLocale localeWithLocaleIdentifier:@"en_US"];
    
    return [formatter stringFromDate:NSDate.date];
}

#pragma mark -

@end

@implementation NSMutableURLRequest (M5HMAC)

#pragma mark - NSMutableURLRequest+M5HMAC -

#pragma mark Methods

- (void)M5_HMACSignWithID:(NSString *)ID secret:(NSString *)secret {
    NSString *bodyMD5 = self.M5_HTTPBodyMD5;
    NSString *httpDate = [self valueForHTTPHeaderField:@"Date"] ?: NSDate.M5_HTTPDateString;
    
    [self setValue:bodyMD5 forHTTPHeaderField:@"Content-MD5"];
    [self setValue:httpDate forHTTPHeaderField:@"Date"];
    
    NSString *encryptedCanonicalString = [self.M5_HMACCanonicalString M5_SHA1WithSecret:secret];
    NSString *header = [NSString stringWithFormat:@"APIAuth %@:%@", ID, encryptedCanonicalString];
    
    [self addValue:header forHTTPHeaderField:@"Authorization"];
}

#pragma mark -

#pragma mark - NSMutableURLRequest+M5HMAC (Private) -

#pragma mark Properties

- (NSString *)M5_URIString {
    NSString *query = self.URL.query.length > 0 ? [NSString stringWithFormat:@"?%@", decodeURLString(self.URL.query)] : @"";
    
    return [NSString stringWithFormat:@"%@%@", self.URL.relativePath, query];
}

- (NSString *)M5_HTTPBodyMD5 {
    return [[NSString alloc] initWithData:self.HTTPBody encoding:NSUTF8StringEncoding].M5_base64MD5;
}

- (NSString *)M5_HMACCanonicalString {
    NSString *bodyMD5 = self.M5_HTTPBodyMD5;
    NSString *uri = self.M5_URIString;
    NSString *httpDate = [self valueForHTTPHeaderField:@"Date"];
    
    [self setValue:bodyMD5 forHTTPHeaderField:@"Content-MD5"];
    [self setValue:httpDate forHTTPHeaderField:@"Date"];
    
    return [NSString stringWithFormat:@"%@,%@,%@,%@", [self valueForHTTPHeaderField:@"Content-Type"], bodyMD5, uri, httpDate];
}

#pragma mark Functions

NSString* decodeURLString(NSString *string) {
    return (__bridge NSString *) CFURLCreateStringByReplacingPercentEscapesUsingEncoding(NULL, (__bridge CFStringRef) string, CFSTR(""), kCFStringEncodingUTF8);
}

#pragma mark -

@end
