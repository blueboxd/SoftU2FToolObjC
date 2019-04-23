//
//  SoftU2FToolObjCAppDelegate.h
//  SoftU2FToolObjC
//
//  Created by bluebox on 18/10/28.
//  Copyright 2018 __MyCompanyName__. All rights reserved.
//

#import <Cocoa/Cocoa.h>
#import <Security/Security.h>
#import <Security/SecRandom.h>
#include "softu2f.h"
#include "u2f_hid.h"

#undef I // complex.h defines some crazy `I` macro...
#import <openssl/asn1.h>
#import <openssl/ec.h>
#import <openssl/ecdsa.h>
#import <openssl/evp.h>
#import <openssl/objects.h>
#import <openssl/pem.h>
#import <openssl/hmac.h>
//#import <openssl/hkdf.h>

#include "SelfSignedCertificate.h"
@interface SoftU2FToolObjCAppDelegate : NSObject <NSApplicationDelegate> {
	softu2f_ctx *u2fctx;

}
@property (nonatomic) BOOL enabled;

@property (strong,nonatomic) NSDictionary *appIDs;
@property (strong,nonatomic) NSStatusItem *statusItem;

@property (strong,nonatomic) IBOutlet NSMenu *statusMenu;
@property (strong,nonatomic) IBOutlet NSWindow *popupWindow;
@property (strong,nonatomic) IBOutlet NSTextField *usageLabel;

- (IBAction) approveButtonAction:(id)sender;
- (IBAction) rejectButtonAction:(id)sender;

- (IBAction) toggleEnabledAction:(id)sender;
- (IBAction) quitAction:(id)sender;

@end
