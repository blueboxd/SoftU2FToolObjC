//
//  SoftU2FToolObjCAppDelegate.m
//  SoftU2FToolObjC
//
//  Created by bluebox on 18/10/28.
//  Copyright 2018 __MyCompanyName__. All rights reserved.
//

#import "SoftU2FToolObjCAppDelegate.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wobjc-protocol-method-implementation"
@implementation NSWindow (NSNotificationWindow)

- (void)center {
	NSPoint pos;
	pos.x = [[NSScreen mainScreen] visibleFrame].origin.x + [[NSScreen mainScreen] visibleFrame].size.width - [self frame].size.width;
	pos.y = [[NSScreen mainScreen] visibleFrame].origin.y + [[NSScreen mainScreen] visibleFrame].size.height - [self frame].size.height;
	
	pos.x -= 16;
	pos.y -= 16;
	[self setFrameOrigin : pos];
	[self setLevel:NSScreenSaverWindowLevel];
}

@end
#pragma clang diagnostic pop

@implementation SoftU2FToolObjCAppDelegate

- (void)applicationDidFinishLaunching:(NSNotification *)aNotification {
	// Insert code here to initialize your application 
	
	[self startU2FHID];
	
	self.statusItem = [[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength];
	self.statusItem.menu = self.statusMenu;
//	self.statusItem.title = @"Y";
	self.statusItem.highlightMode = YES;
	self.statusItem.image = [NSImage imageNamed:@"fido-c"];
	
	self.appIDs = @{
		plain(@"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"):@"bogus",
		sha256(@"https://u2f.bin.coffee"):@"u2f.bin.coffee",
		sha256(@"https://alexander.sagen.me"):@"alexander.sagen.me",
		
		sha256(@"https://github.com/u2f/trusted_facets"): @"github.com",
		sha256(@"https://demo.yubico.com"): @"demo.yubico.com",
		sha256(@"https://www.dropbox.com/u2f-app-id.json"): @"dropbox.com",
		sha256(@"https://www.gstatic.com/securitykey/origins.json"): @"google.com",
		sha256(@"https://vault.bitwarden.com/app-id.json"): @"vault.bitwarden.com",
		sha256(@"https://keepersecurity.com"): @"keepersecurity.com",
		sha256(@"https://api-9dcf9b83.duosecurity.com"): @"api-9dcf9b83.duosecurity.com",
		sha256(@"https://dashboard.stripe.com"): @"dashboard.stripe.com",
		sha256(@"https://id.fedoraproject.org/u2f-origins.json"): @"id.fedoraproject.org",
		sha256(@"https://lastpass.com"): @"lastpass.com",
		sha256(@"https://twitter.com/account/login_verification/u2f_trusted_facets.json"):@"twitter.com",
		sha256(@"https://u2f.aws.amazon.com/app-id.json"):@"aws.amazon.com",
		
		// WebAuthn rpID
		sha256(@"webauthn.bin.coffee"):@"webauthn.bin.coffee",
		sha256(@"demo.yubico.com"): @"demo.yubico.com",
		sha256(@"webauthndemo.appspot.com"):@"webauthndemo.appspot.com",
	};
}

- (void)applicationDidBecomeActive:(NSNotification *)notification {
//	[NSApp hide:self];
}

- (id)init {
	self = [super init];
	self.enabled = YES;
	return self;
}

- (IBAction) toggleEnabledAction:(id)sender {
	self.enabled = !self.enabled;
	if(self.enabled) {
		[self startU2FHID];
		self.statusItem.image = [NSImage imageNamed:@"fido-c"];
	} else {
		[self stopU2FHID];
		self.statusItem.image = [NSImage imageNamed:@"fido-g"];
	}
}

- (IBAction) quitAction:(id)sender {
	[NSApp terminate:self];
}

- (void)applicationWillTerminate:(NSNotification *)notification {
	[self stopU2FHID];
}

- (void)startU2FHID {
	if(!u2fctx) {
		u2fctx = softu2f_init(0);
	//	softu2f_hid_msg_handler_register(u2fctx, U2FHID_PING, handleMsgRequest);
		softu2f_hid_msg_handler_register(u2fctx, U2FHID_MSG, handleMsgRequest);
	//	softu2f_hid_msg_handler_register(u2fctx, U2FHID_INIT, handleMsgRequest);
	//	softu2f_hid_msg_handler_register(u2fctx, U2FHID_WINK, handleWinkRequest);
		
		[NSThread detachNewThreadSelector:@selector(runLoopThread) toTarget:self withObject:nil];
	}
}

- (void)stopU2FHID {
	if(u2fctx) {
		softu2f_shutdown(u2fctx);
		softu2f_deinit(u2fctx);
		u2fctx = nil;
	}
}

- (void) runLoopThread {
	softu2f_run(u2fctx);
}

- (IBAction) approveButtonAction:(id)sender {
	[[NSApplication sharedApplication] stopModalWithCode:1];
}

- (IBAction) rejectButtonAction:(id)sender {
	[[NSApplication sharedApplication] stopModalWithCode:0];
}
- (void)timeoutModal {
	[NSApp abortModal];
}

- (bool) testUserPresenseFor:(NSString*)msg {
	NSTimer *timer = [NSTimer timerWithTimeInterval:10 target:self selector:@selector(timeoutModal) userInfo:nil repeats:NO];
	[[NSRunLoop mainRunLoop] addTimer:timer forMode:NSModalPanelRunLoopMode];
	
	[self.usageLabel setStringValue:msg];
	NSInteger res = [[NSApplication sharedApplication] runModalForWindow:self.popupWindow];
	[timer invalidate];
	[self.popupWindow orderOut:self];
	
	if(res==NSRunAbortedResponse)
		res = false;

	return res;
}

NSData * signData(NSData *msg,EC_KEY *ec) {
  EVP_MD_CTX *ctx=EVP_MD_CTX_new();
  const unsigned char *cmsg = (const unsigned char *)[msg bytes];
  unsigned char *sig;
  unsigned int len;  EVP_PKEY *pkey;

  if (EC_KEY_check_key(ec) != 1) {
    NSLog(@"error checking key\n");
    EC_KEY_free(ec);
    return nil;
  }

  pkey = EVP_PKEY_new();
  if (pkey == NULL) {
    NSLog(@"failed to init pkey\n");
    EC_KEY_free(ec);
    return nil;
  }

  if (EVP_PKEY_assign_EC_KEY(pkey, ec) != 1) {
    NSLog(@"failed to assing ec to pkey\n");
    EC_KEY_free(ec);
    EVP_PKEY_free(pkey);
    return nil;
  }

  // `ec` memory is managed by `pkey` from here.
  if (EVP_SignInit(ctx, EVP_sha256()) != 1) {
    NSLog(@"failed to init signing context\n");
    EVP_PKEY_free(pkey);
    return nil;
  };
size_t msgLen = (unsigned int)[msg length];
  if (EVP_SignUpdate(ctx, cmsg, msgLen) != 1) {
    NSLog(@"failed to update digest\n");
    EVP_PKEY_free(pkey);
    return nil;
  }

  sig = (unsigned char *)malloc(EVP_PKEY_size(pkey));
  if (sig == NULL) {
    NSLog(@"failed to malloc for sig\n");
    EVP_PKEY_free(pkey);
    return nil;
  }

  if (EVP_SignFinal(ctx, sig, &len, pkey) != 1) {
    NSLog(@"failed to finalize digest\n");
    free(sig);
    EVP_PKEY_free(pkey);
    return nil;
  }

  NSData *res = [[NSData alloc] initWithBytes:sig length:len];
  free(sig);
  return res;
}

typedef enum {
	CommandRegister = 1,
	CommandAuthenticate,
	CommandVersion,
} APUDInst;

typedef struct APDUBody {
	union {
		struct {
			uint8_t challenge[32];
			uint8_t application[32];
		} registerRequest;
		
		struct {
			uint8_t challenge[32];
			uint8_t application[32];
			uint8_t keyHandleLen;
			uint8_t keyHandle[256];
		} authenticateRequest;
	};
} APDUBody;

typedef struct APDUHeader {
	char CLA;
	char INS;
	char P1;
	char P2;
	char Lc[3];
} APDUHeader;

typedef struct APDUPacket {
	APDUHeader header;
	APDUBody body;
} APDUPacket;

bool handleWinkRequest(softu2f_ctx *ctx, softu2f_hid_message *msg) {
	NSLog(@"cmd:0x%x(U2FHID_WINK)",msg->cmd);

	softu2f_hid_message res;
	res.cid = msg->cid;
	res.cmd = msg->cmd;
	res.bcnt = msg->bcnt;
	res.data = msg->data;
	NSLog(@"send: ack");
	softu2f_hid_msg_send(ctx, &res);
	return true;
}

bool handleMsgRequest(softu2f_ctx *ctx, softu2f_hid_message *msg) {
	NSLog(@"handleMsgRequest:cmd:0x%x(U2FHID_MSG)",msg->cmd);
	NSLog(@"rcv: data(%u):%@", (unsigned int)CFDataGetLength(msg->data),msg->data);

	softu2f_hid_message res;
	res.cid = msg->cid;
	res.cmd = U2FHID_MSG;

	bool handled=false;

	APUDInst inst = getAPDUInst(msg->data);
	switch (inst) {
		case CommandRegister:
			handled = handleRegisterRequest(ctx,msg,&res);
		break;
		
		case CommandAuthenticate:
			handled = handleAuthenticateRequest(ctx,msg,&res);
		break;
		
		case CommandVersion:
			handled = handleVersionRequest(msg,&res);
		break;
	}

	if(handled) {
		NSLog(@"send: data(%u):%@", (unsigned int)CFDataGetLength(res.data), res.data );
		softu2f_hid_msg_send(ctx, &res);
	}
	return handled;
}

APUDInst getAPDUInst(CFDataRef data) {
	APDUPacket *apdu = (APDUPacket*)CFDataGetBytePtr(data);
	return apdu->header.INS;
}

char responseNoErr[] = {0x90,0x00};
char responseConditionsNotStatisfied[] = {0x69,0x85};
char responseCmdNotAllowed[] = {0x69,0x86};
char responseWrongData[] = {0x6A,0x80};
char responseSomethingWrong[] = {0x6f,0x00};

NSString *sha256(NSString*str){
	NSData *buf = [NSData dataWithBytes:[str cStringUsingEncoding:NSASCIIStringEncoding] length:[str length]];
	uint8_t digest[SHA256_DIGEST_LENGTH];
	
	SHA256(buf.bytes,buf.length, digest);
	return [[NSData dataWithBytes:digest length:SHA256_DIGEST_LENGTH] description];
}

NSString *plain(NSString*str) {
	NSData *buf = [NSData dataWithBytes:[str cStringUsingEncoding:NSASCIIStringEncoding] length:[str length]];
	return [buf description];
}

NSString* getAppID(CFDataRef applicationParameter) {

	NSString *applicationParameterStr = [(__bridge NSData*)applicationParameter description];
	NSString *res = ((SoftU2FToolObjCAppDelegate*)[NSApp delegate]).appIDs[applicationParameterStr];

	if(res==nil)
		return @"unidentified site";
	return res;
}

bool handleRegisterRequest(softu2f_ctx *ctx ,const softu2f_hid_message *msg, struct softu2f_hid_message *res) {
	NSLog(@"handleRegisterRequest:%@", msg->data);
	APDUPacket *apdu = (APDUPacket*)CFDataGetBytePtr(msg->data);
	APDUBody body = apdu->body;
	
	CFDataRef challenge = CFDataCreate(nil,body.registerRequest.challenge,sizeof(body.registerRequest.challenge));
	CFDataRef application = CFDataCreate(nil,body.registerRequest.application,sizeof(body.registerRequest.application));
	NSLog(@"challenge:%@",challenge);
	NSLog(@"application:%@",application);

	NSString *appID = getAppID(application);
	if([appID isEqualToString:@"bogus"]) {
		CFRelease(application);
		CFRelease(challenge);
		res->bcnt = sizeof(responseCmdNotAllowed);
		res->data = CFDataCreate(NULL, responseCmdNotAllowed, res->bcnt);
		return true;		
	}
	
   __block BOOL approved = NO;
    dispatch_sync(dispatch_get_main_queue(), ^{
        approved = [(SoftU2FToolObjCAppDelegate*)[NSApp delegate] testUserPresenseFor:[NSString stringWithFormat:@"Registration Request from:\n %@",appID]];
    });
    
	if(!approved) {
		CFRelease(application);
		CFRelease(challenge);
		res->bcnt = sizeof(responseCmdNotAllowed);
		res->data = CFDataCreate(NULL, responseCmdNotAllowed, res->bcnt);
		return true;
	}

	CFDataRef privKey, pubKey, keyHandle;
	if(!generateKeyPair(application, &privKey, &pubKey, &keyHandle)) {
		CFRelease(application);
		CFRelease(challenge);
		res->bcnt = sizeof(responseSomethingWrong);
		res->data = CFDataCreate(NULL, responseSomethingWrong, res->bcnt);
		return true;
	}
	CFRelease(application);
	CFRelease(challenge);
	
	char reserved[1] = {0x00};
	size_t bufSize = 1+sizeof(body.registerRequest.application)+sizeof(body.registerRequest.challenge)+CFDataGetLength(keyHandle)+CFDataGetLength(pubKey);
	
	CFMutableDataRef buf = CFDataCreateMutable(nil, bufSize);
	CFDataAppendBytes(buf, reserved,sizeof(reserved));
	CFDataAppendBytes(buf, body.registerRequest.application, sizeof(body.registerRequest.application));
	CFDataAppendBytes(buf, body.registerRequest.challenge, sizeof(body.registerRequest.challenge));
	
	CFDataAppendBytes(buf, CFDataGetBytePtr(keyHandle), CFDataGetLength(keyHandle));
	CFDataAppendBytes(buf, CFDataGetBytePtr(pubKey), CFDataGetLength(pubKey));
	
	CFDataRef signature = (__bridge_retained CFDataRef)[SelfSignedCertificate signData:(__bridge_transfer NSData*)buf];

	char reservedResponse[1] = {0x05};
	NSData *cert = [SelfSignedCertificate toDer];
	
	uint8_t keyHandleSize = CFDataGetLength(keyHandle);
	size_t responseSize = 1+CFDataGetLength(pubKey)+1+CFDataGetLength(keyHandle)+[cert length]+CFDataGetLength(signature)+sizeof(responseNoErr);
	CFMutableDataRef response = CFDataCreateMutable(nil, responseSize);

	CFDataAppendBytes(response,reservedResponse,1);
	CFDataAppendBytes(response, CFDataGetBytePtr(pubKey), CFDataGetLength(pubKey));
	CFDataAppendBytes(response,&keyHandleSize,1);
	CFDataAppendBytes(response, CFDataGetBytePtr(keyHandle), CFDataGetLength(keyHandle));
	CFDataAppendBytes(response,[cert bytes],[cert length]);
	CFDataAppendBytes(response,CFDataGetBytePtr(signature),CFDataGetLength(signature));
	CFRelease(signature);
	CFRelease(pubKey);
	CFRelease(privKey);
	CFRelease(keyHandle);

	CFDataAppendBytes(response,responseNoErr,sizeof(responseNoErr));
	
	res->bcnt = CFDataGetLength(response);
	res->data = response;
	return true;
}

bool handleAuthenticateRequest(softu2f_ctx *ctx ,const softu2f_hid_message *msg, struct softu2f_hid_message *res) {
	NSLog(@"handleAuthenticateRequest:%@", msg->data);

	APDUPacket *apdu = (APDUPacket*)CFDataGetBytePtr(msg->data);
	APDUBody body = apdu->body;
	CFDataRef challenge = CFDataCreate(nil,body.registerRequest.challenge,sizeof(body.registerRequest.challenge));
	CFDataRef application = CFDataCreate(nil,body.registerRequest.application,sizeof(body.registerRequest.application));
	CFDataRef keyHandle = CFDataCreate(nil, body.authenticateRequest.keyHandle, body.authenticateRequest.keyHandleLen);

	NSLog(@"challenge:%@",challenge);
	NSLog(@"application:%@",application);
	NSLog(@"keyhandle:%@",keyHandle);
	
	CFDataRef rePrivKey;	
	if(!recoverFromKeyHandle(application, keyHandle, &rePrivKey)) {
		CFRelease(keyHandle);
		CFRelease(application);
		CFRelease(challenge);
		res->bcnt = sizeof(responseWrongData);
		res->data = CFDataCreate(NULL, responseWrongData, res->bcnt);
		return true;
	}
	CFRelease(keyHandle);
	
	NSString *appID = getAppID(application);
	
    __block BOOL approved = NO;
    dispatch_sync(dispatch_get_main_queue(), ^{
        approved = [(SoftU2FToolObjCAppDelegate*)[NSApp delegate] testUserPresenseFor:[NSString stringWithFormat:@"Authentication Request from:\n %@",appID]];
    });
        
    if(!approved) {
		CFRelease(application);
		CFRelease(challenge);
		CFRelease(rePrivKey);

		res->bcnt = sizeof(responseCmdNotAllowed);
		res->data = CFDataCreate(NULL, responseCmdNotAllowed, res->bcnt);
		return true;
	}
	CFRelease(application);
	CFRelease(challenge);
	
	char userPresence[1] = {0x01};
	uint32_t counter[] = {htonl([[NSDate date] timeIntervalSince1970])};
	size_t bufSize = sizeof(body.registerRequest.application)+sizeof(userPresence)+sizeof(counter)+sizeof(body.registerRequest.challenge);
	
	CFMutableDataRef buf = CFDataCreateMutable(nil, bufSize);
	
	CFDataAppendBytes(buf, body.registerRequest.application, sizeof(body.registerRequest.application));
	CFDataAppendBytes(buf, userPresence, sizeof(userPresence));
	CFDataAppendBytes(buf, (UInt8*)counter, sizeof(counter));
	CFDataAppendBytes(buf, body.registerRequest.challenge, sizeof(body.registerRequest.challenge));

	EC_KEY *eckey = recoverECKeyFromPrivatekey(rePrivKey);
	CFRelease(rePrivKey);
	CFDataRef signature = (__bridge_retained CFDataRef)signData((__bridge_transfer NSData*)buf,eckey);
	
	size_t responseSize = 1+sizeof(counter)+CFDataGetLength(signature)+sizeof(responseNoErr);
	CFMutableDataRef response = CFDataCreateMutable(nil, responseSize);

	CFDataAppendBytes(response,userPresence,sizeof(userPresence));
	CFDataAppendBytes(response, (UInt8*)counter,sizeof(counter));
	CFDataAppendBytes(response,CFDataGetBytePtr(signature),CFDataGetLength(signature));
	CFRelease(signature);
	CFDataAppendBytes(response,responseNoErr,sizeof(responseNoErr));
	
	res->bcnt = CFDataGetLength(response);
	res->data = response;
	return true;
}

bool handleVersionRequest(const softu2f_hid_message *msg, struct softu2f_hid_message *res) {
	NSLog(@"handleVersionRequest");
	char raw[] = {'U','2','F','_','V','2',0x90,0x00};

	res->bcnt = sizeof(raw);
	res->data = CFDataCreate(NULL, raw, res->bcnt);
	return true;	
}

uint8_t deviceSecret[] = {
<# define device key #>
};

#define NONCE_BYTES 16

CFDataRef generatePrivateKey(CFDataRef applicationParameter, uint8_t* nonceRandom) {
	CFMutableDataRef buf = CFDataCreateMutable(nil, CFDataGetLength(applicationParameter)+NONCE_BYTES);
	CFDataAppendBytes(buf, CFDataGetBytePtr(applicationParameter), CFDataGetLength(applicationParameter));
	CFDataAppendBytes(buf, nonceRandom, NONCE_BYTES);

	//HKDF(<#uint8_t *out_key#>, <#size_t out_len#>, <#const struct env_md_st *digest#>, <#const uint8_t *secret#>, <#size_t secret_len#>, <#const uint8_t *salt#>, <#size_t salt_len#>, <#const uint8_t *info#>, <#size_t info_len#>);
	
	uint8_t hmacDigest[SHA512_DIGEST_LENGTH];
	unsigned int hmacDigestLen;
	HMAC(EVP_sha3_512(),deviceSecret,sizeof(deviceSecret),CFDataGetBytePtr(buf),CFDataGetLength(buf),hmacDigest,&hmacDigestLen);
	CFRelease(buf);

	uint8_t digest[SHA256_DIGEST_LENGTH];
	unsigned int resultLen=SHA256_DIGEST_LENGTH;
//	HMAC(EVP_sha3_256(),hmacDigest,hmacDigestLen,nonceRandom,NONCE_BYTES,digest,&resultLen);
	PKCS5_PBKDF2_HMAC(hmacDigest, hmacDigestLen, nonceRandom, NONCE_BYTES, 16384, EVP_sha3_512(), SHA256_DIGEST_LENGTH, digest);
	CFDataRef res = CFDataCreate(nil,digest,resultLen);
	
	NSLog(@"generatePrivateKey:%@",res);
	return res;
}

CFDataRef calculateKeyHandleMAC(CFDataRef applicationParameter, CFDataRef privKey, uint8_t *nonceRandom) {
	CFMutableDataRef keyHandleMACBuf = CFDataCreateMutable(nil, CFDataGetLength(applicationParameter)+CFDataGetLength(privKey));
	uint8_t keyHandleDigest[SHA512_DIGEST_LENGTH],resultDigest[SHA256_DIGEST_LENGTH];
	unsigned int keyHandleDigestLen, resultLen;
	CFDataAppendBytes(keyHandleMACBuf, CFDataGetBytePtr(applicationParameter), CFDataGetLength(applicationParameter));
	CFDataAppendBytes(keyHandleMACBuf, CFDataGetBytePtr(privKey), CFDataGetLength(privKey));
	HMAC(EVP_sha3_512(),deviceSecret,sizeof(deviceSecret),CFDataGetBytePtr(keyHandleMACBuf),CFDataGetLength(keyHandleMACBuf),keyHandleDigest,&keyHandleDigestLen);
	HMAC(EVP_sha3_256(),keyHandleDigest,keyHandleDigestLen,nonceRandom,NONCE_BYTES,resultDigest,&resultLen);
	CFRelease(keyHandleMACBuf);
	CFDataRef res = CFDataCreate(nil,resultDigest,resultLen);
	
	NSLog(@"calculateKeyHandleMAC:%@",res);
	return res;
}

bool generateKeyPair(CFDataRef applicationParameter, CFDataRef *privKey, CFDataRef *pubKey, CFDataRef *keyHandle) {

	uint8_t nonceRandom[NONCE_BYTES];
	if(SecRandomCopyBytes(kSecRandomDefault, NONCE_BYTES, nonceRandom)!=errSecSuccess) {
		NSLog(@"generateKeyPair: SecRandomCopyBytes failed");
		return false;
	}

	CFDataRef newPrivateKey = generatePrivateKey(applicationParameter, nonceRandom);
	EC_KEY *eckey = recoverECKeyFromPrivatekey(newPrivateKey);

	EC_POINT *publicPoint;
	const EC_GROUP *group = EC_KEY_get0_group(eckey);;
	BN_CTX *ctx = BN_CTX_new();
	
	uint8_t pointbuf[128];
	size_t pointlen;
	point_conversion_form_t form = EC_GROUP_get_point_conversion_form(group);
	
	publicPoint = (EC_POINT*)EC_KEY_get0_public_key(eckey);
	pointlen = EC_POINT_point2oct(group, publicPoint, form, pointbuf, 128, ctx);
	CFDataRef publicKeyData = CFDataCreate(nil, pointbuf, pointlen);
	
	BIGNUM *privateBN;
	uint8_t privatebuf[128];
	size_t privatelen;
	
	privateBN = (BIGNUM*)EC_KEY_get0_private_key(eckey);
	privatelen = BN_bn2mpi(privateBN, privatebuf);
	CFDataRef privateKeyData = CFDataCreate(nil, privatebuf, privatelen);

	CFDataRef keyHandleDigest = calculateKeyHandleMAC(applicationParameter, newPrivateKey, nonceRandom);
	CFRelease(newPrivateKey);

	CFMutableDataRef keyHandleBuf = CFDataCreateMutable(nil, sizeof(nonceRandom)+CFDataGetLength(keyHandleDigest));
	CFDataAppendBytes(keyHandleBuf,nonceRandom,sizeof(nonceRandom));
	CFDataAppendBytes(keyHandleBuf,CFDataGetBytePtr(keyHandleDigest),CFDataGetLength(keyHandleDigest));
	CFRelease(keyHandleDigest);

	*privKey = privateKeyData;
	*pubKey = publicKeyData;
	*keyHandle = keyHandleBuf;
	return true;
}

EC_KEY* recoverECKeyFromPrivatekey(CFDataRef privateKeyData) {
	BN_CTX *rectx=BN_CTX_new();
	EC_KEY *reKey;
	EC_GROUP *reGroup;
	reKey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	reGroup = (EC_GROUP*)EC_KEY_get0_group(reKey);
		
	BIGNUM *rePrivateBN;
	rePrivateBN = BN_new();
	BN_bin2bn(CFDataGetBytePtr(privateKeyData), (int)CFDataGetLength(privateKeyData), rePrivateBN);
	EC_KEY_set_private_key(reKey, rePrivateBN);
	
	EC_POINT *pub_key = NULL;

	pub_key = EC_POINT_new(reGroup);

	if (!EC_POINT_mul(reGroup, pub_key, rePrivateBN, NULL, NULL, rectx)) {
		NSLog(@"recoverECKeyFromPrivatekey: EC_POINT_mul failed");
		return nil;
	}
	EC_KEY_set_public_key(reKey, pub_key);
	
	if(!EC_KEY_check_key(reKey))
		return nil;

	return reKey;
}

bool recoverFromKeyHandle(CFDataRef applicationParameter, CFDataRef keyHandle, CFDataRef *privateKeyData) {
	uint8_t nonceRandom[NONCE_BYTES];
	uint8_t macDigestBuf[SHA256_DIGEST_LENGTH];
	
	if(CFDataGetLength(keyHandle)<(NONCE_BYTES+SHA256_DIGEST_LENGTH)) {
		NSLog(@"recoverFromKeyHandle:keyHandle too short");
		return false;
	}
	
	CFDataGetBytes(keyHandle, CFRangeMake(0, NONCE_BYTES), nonceRandom);
	CFDataGetBytes(keyHandle, CFRangeMake(NONCE_BYTES, SHA256_DIGEST_LENGTH), macDigestBuf);
	CFDataRef hmacDigestData = CFDataCreate(nil, macDigestBuf, SHA256_DIGEST_LENGTH);

	CFDataRef privKey = generatePrivateKey(applicationParameter, nonceRandom);
	
	CFDataRef calculatedHMACDigestData = calculateKeyHandleMAC(applicationParameter, privKey, nonceRandom);
	if(! [(__bridge_transfer NSData*)hmacDigestData isEqualTo:(__bridge_transfer NSData*)calculatedHMACDigestData]) {
		NSLog(@"recoverFromKeyHandle:wrong digest");
		CFRelease(privKey);
		return false;
	}
	
	EC_KEY *eckey = recoverECKeyFromPrivatekey(privKey);
	if(eckey==nil) {
		NSLog(@"recoverFromKeyHandle:wrong EC key");
		CFRelease(privKey);
		return false;
	}
	
	*privateKeyData = privKey;
	return true;
}

@end
