//
//  ViewController.m
//  RSAPublicKey
//
//  Created by yangtu222 on 16/6/29.
//  Copyright © 2016年 yangtu222. All rights reserved.
//

#import "ViewController.h"
#import "RSAPubKey.h"
#import "NSData+RSA.h"

@interface ViewController ()

@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    SecKeyRef pubKey = [RSAPubKey stringToRSAPubKey:@"0E8fPw5rw/t1xobyTbXtZgLNYuBlX3RQy4re0SZerVGNW/LkN92Ycw+aLT0/9bxy/WuY63JOJFmZFVsIAnKhdfZLCoFQPq5nNJ1rUNfJ4J7FWvJoaM69IM/VA3GTdIRGQHgQJIXlXbiGOk+lJfo51Ncb67w2miqucsoS/YcgL0=" andExponent:@"AQAB"];
    
    if( pubKey == nil )
        return;
    
    char testChar = 'A';
    
    NSData* testData = [[NSData alloc] initWithBytes:&testChar length:1];
    NSData* testEncoded = [testData encryptWithRSA:pubKey];
    
    NSLog(@"%@\n", testEncoded);
    
    CFRelease(pubKey);
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}

@end
