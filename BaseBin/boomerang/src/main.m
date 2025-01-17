#import <Foundation/Foundation.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/handoff.h>
#import <libjailbreak/kcall.h>
#import <libfilecom/FCHandler.h>
#import <libjailbreak/launchd.h>

FCHandler *gHandler;

int launchdInitPPLRW(void)
{
	xpc_object_t msg = xpc_dictionary_create_empty();
	xpc_dictionary_set_bool(msg, "jailbreak", true);
	xpc_dictionary_set_uint64(msg, "id", LAUNCHD_JB_MSG_ID_GET_PPLRW);
	xpc_object_t reply = launchd_xpc_send_message(msg);

	int error = xpc_dictionary_get_int64(reply, "error");
	if (error == 0) {
		initPPLPrimitives();
		return 0;
	}
	else {
		return error;
	}
}

void getPrimitives(void)
{
	dispatch_semaphore_t sema = dispatch_semaphore_create(0);
	// Receive PPLRW
	gHandler.receiveHandler = ^(NSDictionary *message)
	{
		JBLogDebug("receiveHandler: message=%p", message);
		NSString *identifier = message[@"id"];
		if (identifier) {
			JBLogDebug("receiveHandler: identifier=%s", identifier.UTF8String);
			if ([identifier isEqualToString:@"receivePPLRW"])
			{
				JBLogDebug("receivePPLRW");
				initPPLPrimitives();
				dispatch_semaphore_signal(sema);
			}
		}
	};
	[gHandler sendMessage:@{ @"id" : @"getPPLRW", @"pid" : @(getpid()) }];

	dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

	int ret = recoverPACPrimitives();
	JBLogDebug("recoverPACPrimitives=%d", ret);

	// Tell launchd we're done, this will trigger the userspace reboot (that this process should survive)
	[gHandler sendMessage:@{ @"id" : @"primitivesInitialized" }];
}

void sendPrimitives(void)
{
	dispatch_semaphore_t sema = dispatch_semaphore_create(0);
	gHandler.receiveHandler = ^(NSDictionary *message) {
		NSString *identifier = message[@"id"];
		if (identifier) {
			if ([identifier isEqualToString:@"getPPLRW"]) {
				int ret = handoffPPLPrimitives(1);
				JBLogDebug("handoffPPLPrimitives=%d", ret);				
				[gHandler sendMessage:@{@"id" : @"receivePPLRW", @"errorCode" : @(ret), @"boomerangPid" : @(getpid())}];
			}
			else if ([identifier isEqualToString:@"signThreadState"]) {
				uint64_t actContextKptr = [(NSNumber*)message[@"actContext"] unsignedLongLongValue];
				int ret = signState(actContextKptr);
				JBLogDebug("signState=%d", ret);
				[gHandler sendMessage:@{@"id" : @"signedThreadState"}];
			}
			else if ([identifier isEqualToString:@"primitivesInitialized"])
			{
				dispatch_semaphore_signal(sema); // DONE, exit
			}
		}
	};
	dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
}

int main(int argc, char* argv[])
{
	JBLogDebug("boomerang comming=%d", getpid());

	setsid();
	gHandler = [[FCHandler alloc] initWithReceiveFilePath:jbrootPath(@"/var/.communication/launchd_to_boomerang") sendFilePath:jbrootPath(@"/var/.communication/boomerang_to_launchd")];
	getPrimitives();

int patch_proc_csflags(int pid);
int unrestrict(pid_t pid, int (*callback)(pid_t pid), bool should_resume);

	//!
	int ret=unrestrict(1, patch_proc_csflags, true);
	JBLogDebug("boomerang unrestrict=%d", ret);

	sendPrimitives();
	JBLogDebug("boomerang exit!");
	return 0;
}