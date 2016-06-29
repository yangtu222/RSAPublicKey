//
//  NSData+RSA.m
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

#import "NSData+RSA.h"
#import <Security/Security.h>

@implementation NSData (RSA)

- (NSData *)encryptWithRSA:(SecKeyRef) pubKey;
{
    const uint8_t *srcbuf = (const uint8_t *)[self bytes];
    size_t srclen = (size_t)self.length;
    
    size_t block_size = SecKeyGetBlockSize(pubKey) * sizeof(uint8_t);
    void *outbuf = malloc(block_size);
    size_t src_block_size = block_size - 11;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){

        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyEncrypt(pubKey,
                               kSecPaddingPKCS1,
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        }else{
            [ret appendBytes:outbuf length:outlen];
        }
    }
    
    free(outbuf);

    return ret;
}

- (NSData *)decryptWithRSA:(SecKeyRef) pubKey
{
    if( pubKey == nil )
        return nil;
    
    const uint8_t *srcbuf = (const uint8_t *)[self bytes];
    size_t srclen = (size_t)self.length;
    
    size_t block_size = SecKeyGetBlockSize(pubKey) * sizeof(uint8_t);
    UInt8 *outbuf = malloc(block_size);
    memset(outbuf, 0, block_size);
    size_t src_block_size = block_size;
    
    NSMutableData *ret = [[NSMutableData alloc] init];
    for(int idx=0; idx<srclen; idx+=src_block_size){

        size_t data_len = srclen - idx;
        if(data_len > src_block_size){
            data_len = src_block_size;
        }
        
        size_t outlen = block_size;
        OSStatus status = noErr;
        status = SecKeyDecrypt(pubKey,
                               kSecPaddingNone, //using padding none to decrypt
                               srcbuf + idx,
                               data_len,
                               outbuf,
                               &outlen
                               );
        if (status != 0) {
            NSLog(@"SecKeyEncrypt fail. Error Code: %d", status);
            ret = nil;
            break;
        }else{
            
            //handle the padding.
            //Below is tested with java rsa, not tested with C# or others.
            int idxFirstZero = -1;
            int idxNextZero = -1;
            
            for ( int i = 0; i < outlen; i++ ) {
                if ( outbuf[i] == 0 || outbuf[i] == 0x1 ) {
                    if ( idxFirstZero < 0 ) {
                        idxFirstZero = i;
                    } else {
                        idxNextZero = i;
                        break;
                    }
                }
            }
            
            [ret appendBytes:&outbuf[idxNextZero+1] length: outlen - idxNextZero-1];
            memset(outbuf, 0, block_size);
        }
    }
    
    free(outbuf);
    return ret;
}

@end
