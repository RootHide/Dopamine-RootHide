#import <Foundation/Foundation.h>
#import <libjailbreak/libjailbreak.h>
#import <libjailbreak/handoff.h>
#import <libjailbreak/kcall.h>
#import <libjailbreak/launchd.h>
#import <libfilecom/FCHandler.h>
#import <mach-o/dyld.h>
#import <spawn.h>

#import <sandbox.h>
#import "spawn_hook.h"
#import "xpc_hook.h"
#import "daemon_hook.h"
#import "ipc_hook.h"
#include "crashreporter.h"
#import "../systemhook/src/common.h"

bool gFirstLoad = false;

int gLaunchdImageIndex = -1;

char HOOK_DYLIB_PATH[PATH_MAX] = {0}; //"/usr/lib/systemhook.dylib"

NSString *generateSystemWideSandboxExtensions(BOOL ext)
{
	NSMutableString *extensionString = [NSMutableString new];

	char jbrootbase[PATH_MAX];
	char jbrootsecondary[PATH_MAX];
	snprintf(jbrootbase, sizeof(jbrootbase), "/private/var/containers/Bundle/Application/.jbroot-%s/", JBRAND);
	snprintf(jbrootsecondary, sizeof(jbrootsecondary), "/private/var/mobile/Containers/Shared/AppGroup/.jbroot-%s/", JBRAND);

	[extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file("com.apple.app-sandbox.read", jbrootbase, 0)]];
	[extensionString appendString:@"|"];
	[extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file("com.apple.sandbox.executable", jbrootbase, 0)]];
	[extensionString appendString:@"|"];

	char* class = ext ? "com.apple.app-sandbox.read-write" : "com.apple.app-sandbox.read";
	[extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file(class, jbrootsecondary, 0)]];
	[extensionString appendString:@"|"];
	// [extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_file("com.apple.sandbox.executable", jbrootsecondary, 0)]];
	// [extensionString appendString:@"|"];

	// Ensure the whole system has access to com.opa334.jailbreakd.systemwide
	char service_name[128];
	snprintf(service_name,sizeof(service_name),"com.opa334.jailbreakd.systemwide-%s",JBRAND);
	[extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_mach("com.apple.app-sandbox.mach", service_name, 0)]];
	[extensionString appendString:@"|"];
	[extensionString appendString:[NSString stringWithUTF8String:sandbox_extension_issue_mach("com.apple.security.exception.mach-lookup.global-name", service_name, 0)]];

	return extensionString;
}

__attribute__((constructor)) static void initializer(void)
{
	crashreporter_start();

	bool comingFromUserspaceReboot = bootInfo_getUInt64(@"environmentInitialized");
	if (comingFromUserspaceReboot) {
		JBLogDebug("comingFromUserspaceReboot=1");

		// super hacky fix to support OTA updates from 1.0.x to 1.1
		// I hate it, but there is no better way :/
		NSURL *disabledLaunchDaemonURL = [NSURL fileURLWithPath:jbrootPath(@"/basebin/LaunchDaemons/Disabled") isDirectory:YES];
		NSArray<NSURL *> *disabledLaunchDaemonPlistURLs = [[NSFileManager defaultManager] contentsOfDirectoryAtURL:disabledLaunchDaemonURL includingPropertiesForKeys:nil options:0 error:nil];
		for (NSURL *disabledLaunchDaemonPlistURL in disabledLaunchDaemonPlistURLs) {
			patchBaseBinLaunchDaemonPlist(disabledLaunchDaemonPlistURL.path);
		}

		// Launchd was already initialized before, we are coming from a userspace reboot... recover primitives
		// First get PPLRW primitives
		__block pid_t boomerangPid = 0;
		dispatch_semaphore_t sema = dispatch_semaphore_create(0);
		FCHandler *handler = [[FCHandler alloc] initWithReceiveFilePath:jbrootPath(@"/var/.communication/boomerang_to_launchd") sendFilePath:jbrootPath(@"/var/.communication/launchd_to_boomerang")];
		handler.receiveHandler = ^(NSDictionary *message) {
			JBLogDebug("receiveHandler: message=%p", message);
			NSString *identifier = message[@"id"];
			if (identifier) {
				JBLogDebug("receiveHandler: identifier=%s", identifier.UTF8String);
				if ([identifier isEqualToString:@"receivePPLRW"])
				{
					boomerangPid = [(NSNumber*)message[@"boomerangPid"] intValue];
					JBLogDebug("receiveHandler: boomerangPid=%d", boomerangPid);
					initPPLPrimitives();
					dispatch_semaphore_signal(sema);
				}
			}
		};
		[handler sendMessage:@{ @"id" : @"getPPLRW" }];
		dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
		int ret = recoverPACPrimitives();
		JBLogDebug("recoverPACPrimitives=%d", ret);
		[handler sendMessage:@{ @"id" : @"primitivesInitialized" }];
		[[NSFileManager defaultManager] removeItemAtPath:jbrootPath(@"/var/.communication") error:nil];
		if (boomerangPid != 0) {
			int status;
			waitpid(boomerangPid, &status, WEXITED);
			waitpid(boomerangPid, &status, 0);
		}
		bootInfo_setObject(@"jbdIconCacheNeedsRefresh", @1);
	}
	else {
		// Launchd hook loaded for first time, get primitives from jailbreakd
		int ret = jbdInitPPLRW();
		JBLogDebug("jbdInitPPLRW=%d", ret);
		int ret2 = recoverPACPrimitives();
		JBLogDebug("jbdInitPPLRW=%d", ret2);
		
		gFirstLoad = true;
	}

	for (int i = 0; i < _dyld_image_count(); i++) {
		if(!strcmp(_dyld_get_image_name(i), "/sbin/launchd")) {
			gLaunchdImageIndex = i;
			break;
		}
	}

	//set global var first
	JBRAND = strdup(((NSString*)bootInfo_getObject(@"JBRAND")).UTF8String);
	JBROOT = strdup(((NSString*)bootInfo_getObject(@"JBROOT")).UTF8String);

	// System wide sandbox extensions and root path
	JB_SandboxExtensions = strdup(generateSystemWideSandboxExtensions(NO).UTF8String);
	JB_SandboxExtensions2 = strdup(generateSystemWideSandboxExtensions(YES).UTF8String);
	JB_RootPath = strdup(JBROOT);

	if(comingFromUserspaceReboot)
	{
		NSString* systemhookFilePath = [NSString stringWithFormat:@"%@/systemhook-%s.dylib", jbrootPath(@"/basebin"), JBRAND];
		
		int unsandbox(const char* dir, const char* file);
		unsandbox("/usr/lib", systemhookFilePath.fileSystemRepresentation);

		//new "real path"
		snprintf(HOOK_DYLIB_PATH, sizeof(HOOK_DYLIB_PATH), "/usr/lib/systemhook-%s.dylib", JBRAND);
	}

	proc_set_debugged_pid(getpid(), false);
	initXPCHooks();
	initDaemonHooks();
	initSpawnHooks();
	initIPCHooks();

	// This will ensure launchdhook is always reinjected after userspace reboots
	// As this launchd will pass environ to the next launchd...
	setenv("DYLD_INSERT_LIBRARIES", jbrootPath(@"/basebin/launchdhook.dylib").fileSystemRepresentation, 1);

	bootInfo_setObject(@"environmentInitialized", @1);
}