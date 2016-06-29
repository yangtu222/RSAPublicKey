//
//  RSAPubKey.m
//
//  Version 1.0.0
//
//  Created by yangtu222 on 2016.06.30.
//  Copyright (C) 2016, andlisoft.com.
//
//  Distributed under the permissive zlib License
//  Get the latest version from here:
//
//  https://github.com/yangtu222/RSAPublicKey
//
//  This software is provided 'as-is', without any express or implied
//  warranty.  In no event will the authors be held liable for any damages
//  arising from the use of this software.
//
//  Permission is granted to anyone to use this software for any purpose,
//  including commercial applications, and to alter it and redistribute it
//  freely, subject to the following restrictions:
//
//  1. The origin of this software must not be misrepresented; you must not
//  claim that you wrote the original software. If you use this software
//  in a product, an acknowledgment in the product documentation would be
//  appreciated but is not required.
//
//  2. Altered source versions must be plainly marked as such, and must not be
//  misrepresented as being the original software.
//
//  3. This notice may not be removed or altered from any source distribution.
//

#import <Foundation/Foundation.h>
#import "RSAPubKey.h"
#import "NSData+Base64.h"
#import "BasicEncodingRules.h"

@implementation RSAPubKey

+ (SecKeyRef) stringToRSAPubKey: (NSString*) modulus andExponent:(NSString*) exponent
{
    NSData* modulusData = [NSData dataWithBase64EncodedString: modulus];
    NSData* exponentData = [NSData dataWithBase64EncodedString: exponent];

    return [RSAPubKey dataRSAPubKey: modulusData andExponent: exponentData];
}

+ (SecKeyRef) dataRSAPubKey: (NSData*) modulus andExponent:(NSData*) exponent
{
    if( modulus == nil || exponent == nil)
        return nil;

    NSMutableArray *testArray = [[NSMutableArray alloc] init];
    const char fixByte = 0;
    NSMutableData * fixedModule = [NSMutableData dataWithBytes:&fixByte length:1];
    [fixedModule appendData:modulus];
    [testArray addObject:fixedModule];
    [testArray addObject:exponent];
    NSData *pubKey = [testArray berData];
    if( pubKey == nil ) {
        return nil;
    }

	//a tag to read/write keychain storage
	NSString *tag = @"LiveStorage_PubKey";
	NSData *d_tag = [NSData dataWithBytes:[tag UTF8String] length:[tag length]];
	
	// Delete any old lingering key with the same tag
	NSMutableDictionary *publicKey = [[NSMutableDictionary alloc] init];
	[publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
	[publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	[publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
    SecItemDelete((__bridge CFDictionaryRef)publicKey);

    // Add persistent version of the key to system keychain
	[publicKey setObject:pubKey forKey:(__bridge id)kSecValueData];
	[publicKey setObject:(__bridge id) kSecAttrKeyClassPublic forKey:(__bridge id) kSecAttrKeyClass];
	[publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id) kSecReturnPersistentRef];
	
	CFTypeRef persistKey = nil;
	OSStatus status = SecItemAdd((__bridge CFDictionaryRef)publicKey, &persistKey);
	if (persistKey != nil){
		CFRelease(persistKey);
	}
	if ((status != noErr) && (status != errSecDuplicateItem)) {
		return nil;
	}
    
    publicKey = [[NSMutableDictionary alloc] init];
    
    [publicKey setObject:(__bridge id) kSecClassKey forKey:(__bridge id)kSecClass];
    [publicKey setObject:d_tag forKey:(__bridge id)kSecAttrApplicationTag];
	[publicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
	[publicKey setObject:(__bridge id) kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
	
	// Now fetch the SecKeyRef version of the key
	SecKeyRef keyRef = nil;
	status = SecItemCopyMatching((__bridge CFDictionaryRef)publicKey, (CFTypeRef *)&keyRef);
	if(status != noErr){
		return nil;
	}
    return keyRef;
}

@end
