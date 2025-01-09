#include "common.h"

#include <mach-o/dyld.h>
#include <dlfcn.h>
#include <sys/sysctl.h>
#include <sys/stat.h>
#include <paths.h>
#include <util.h>
#include "sandbox.h"

extern char**environ;

int ptrace(int request, pid_t pid, caddr_t addr, int data);
#define PT_ATTACH       10      /* trace some running process */
#define PT_ATTACHEXC    14      /* attach to running process with signal exception */

void* dlopen_from(const char* path, int mode, void* addressInCaller);
void* dlopen_audited(const char* path, int mode);
bool dlopen_preflight(const char* path);

#define DYLD_INTERPOSE(_replacement,_replacee) \
   __attribute__((used)) static struct{ const void* replacement; const void* replacee; } _interpose_##_replacee \
			__attribute__ ((section ("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };

void unsandbox(void) {
	char extensionsCopy[strlen(JB_SandboxExtensions)];
	strcpy(extensionsCopy, JB_SandboxExtensions);
	char *extensionToken = strtok(extensionsCopy, "|");
	while (extensionToken != NULL) {
		sandbox_extension_consume(extensionToken);
		extensionToken = strtok(NULL, "|");
	}
}

static char *gExecutablePath = NULL;
static void loadExecutablePath(void)
{
	uint32_t bufsize = 0;
	_NSGetExecutablePath(NULL, &bufsize);
	char *executablePath = malloc(bufsize);
	_NSGetExecutablePath(executablePath, &bufsize);
	if (executablePath) {
		gExecutablePath = realpath(executablePath, NULL);
		free(executablePath);
	}
}
static void freeExecutablePath(void)
{
	if (gExecutablePath) {
		free(gExecutablePath);
		gExecutablePath = NULL;
	}
}

void killall(const char *executablePathToKill, bool softly)
{
	static int maxArgumentSize = 0;
	if (maxArgumentSize == 0) {
		size_t size = sizeof(maxArgumentSize);
		if (sysctl((int[]){ CTL_KERN, KERN_ARGMAX }, 2, &maxArgumentSize, &size, NULL, 0) == -1) {
			perror("sysctl argument size");
			maxArgumentSize = 4096; // Default
		}
	}
	int mib[3] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL};
	struct kinfo_proc *info;
	size_t length;
	int count;
	
	if (sysctl(mib, 3, NULL, &length, NULL, 0) < 0)
		return;
	if (!(info = malloc(length)))
		return;
	if (sysctl(mib, 3, info, &length, NULL, 0) < 0) {
		free(info);
		return;
	}
	count = length / sizeof(struct kinfo_proc);
	for (int i = 0; i < count; i++) {
		pid_t pid = info[i].kp_proc.p_pid;
		if (pid == 0) {
			continue;
		}
		size_t size = maxArgumentSize;
		char* buffer = (char *)malloc(length);
		if (sysctl((int[]){ CTL_KERN, KERN_PROCARGS2, pid }, 3, buffer, &size, NULL, 0) == 0) {
			char *executablePath = buffer + sizeof(int);
			if (strcmp(executablePath, executablePathToKill) == 0) {
				if(softly)
				{
					kill(pid, SIGTERM);
				}
				else
				{
					kill(pid, SIGKILL);
				}
			}
		}
		free(buffer);
	}
	free(info);
}

int posix_spawn_hook(pid_t *restrict pidp, const char *restrict path,
					   const posix_spawn_file_actions_t *restrict file_actions,
					    posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	if(!path) { //Don't crash here due to bad posix_spawn call
		return spawn_hook_common(pidp, path, file_actions, attrp, argv, envp, posix_spawn);
	}

	int ret = -1;

	posix_spawnattr_t attr=NULL;
	if(!attrp) {
		attrp = &attr;
		posix_spawnattr_init(&attr);
	}

	short flags = 0;
	posix_spawnattr_getflags(attrp, &flags);

	#define POSIX_SPAWN_PROC_TYPE_DRIVER 0x700
	int posix_spawnattr_getprocesstype_np(const posix_spawnattr_t * __restrict, int * __restrict) __API_AVAILABLE(macos(10.8), ios(6.0));

	int proctype = 0;
	posix_spawnattr_getprocesstype_np(attrp, &proctype);

	bool suspend = (proctype != POSIX_SPAWN_PROC_TYPE_DRIVER);
	bool should_resume = suspend && (flags&POSIX_SPAWN_START_SUSPENDED)==0;
	bool patch_exec = suspend && (flags&POSIX_SPAWN_SETEXEC) != 0;

	if(suspend) {
		posix_spawnattr_setflags(attrp, flags|POSIX_SPAWN_START_SUSPENDED);
	}

	if(patch_exec) {
		if(jbdswPatchExecAdd(path, should_resume)!=0) { //jdb fault?
			// restore flags
			posix_spawnattr_setflags(attrp, flags);
			ret = 199;
			goto end;
		}
	}
	
	int pid=0;
	ret = spawn_hook_common(&pid, path, file_actions, attrp, argv, envp, posix_spawn);
	if(pidp) *pidp=pid;

	// restore flags, maybe caller will use it again?
	posix_spawnattr_setflags(attrp, flags);

	if(patch_exec) { //exec failed?
		jbdswPatchExecDel(path);
	}
	else if(ret==0 && pid>0) {

		if(suspend && jbdswPatchSpawn(pid, should_resume)!=0) //jdb fault? kill
		{
			kill(pid, SIGKILL);
			ret = 198;
			goto end;
		}
	}

end:
	if(attr) posix_spawnattr_destroy(&attr);
	
	return ret;
}

int posix_spawnp_hook(pid_t *restrict pid, const char *restrict file,
					   const posix_spawn_file_actions_t *restrict file_actions,
					    posix_spawnattr_t *restrict attrp,
					   char *const argv[restrict],
					   char *const envp[restrict])
{
	return resolvePath(file, NULL, ^int(char *path) {
		return posix_spawn_hook(pid, path, file_actions, attrp, argv, envp);
	});
}


int execve_hook(const char *path, char *const argv[], char *const envp[])
{
	posix_spawnattr_t attr = NULL;
	posix_spawnattr_init(&attr);
	posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETEXEC);
	int result = posix_spawn_hook(NULL, path, NULL, &attr, argv, envp);
	if (attr) {
		posix_spawnattr_destroy(&attr);
	}

	if(result != 0) { // posix_spawn will return errno and restore errno if it fails
		errno = result; // so we need to set errno by ourself
		return -1;
	}

	return result;
}

int execle_hook(const char *path, const char *arg0, ... /*, (char *)0, char *const envp[] */)
{
	va_list args;
	va_start(args, arg0);

	// Get argument count
	va_list args_copy;
	va_copy(args_copy, args);
	int arg_count = 1;
	for (char *arg = va_arg(args_copy, char *); arg != NULL; arg = va_arg(args_copy, char *)) {
		arg_count++;
	}
	va_end(args_copy);

	char *argv[arg_count+1];
	argv[0] = (char*)arg0;
	for (int i = 0; i < arg_count-1; i++) {
		char *arg = va_arg(args, char*);
		argv[i+1] = arg;
	}
	argv[arg_count] = NULL;

	char *nullChar = va_arg(args, char*);

	char **envp = va_arg(args, char**);
	return execve_hook(path, argv, envp);
}

int execlp_hook(const char *file, const char *arg0, ... /*, (char *)0 */)
{
	va_list args;
	va_start(args, arg0);

	// Get argument count
	va_list args_copy;
	va_copy(args_copy, args);
	int arg_count = 1;
	for (char *arg = va_arg(args_copy, char*); arg != NULL; arg = va_arg(args_copy, char*)) {
		arg_count++;
	}
	va_end(args_copy);

	char **argv = malloc((arg_count+1) * sizeof(char *));
	argv[0] = (char*)arg0;
	for (int i = 0; i < arg_count-1; i++) {
		char *arg = va_arg(args, char*);
		argv[i+1] = arg;
	}
	argv[arg_count] = NULL;

	int r = resolvePath(file, NULL, ^int(char *path) {
		return execve_hook(path, argv, environ);
	});

	free(argv);

	return r;
}

int execl_hook(const char *path, const char *arg0, ... /*, (char *)0 */)
{
	va_list args;
	va_start(args, arg0);

	// Get argument count
	va_list args_copy;
	va_copy(args_copy, args);
	int arg_count = 1;
	for (char *arg = va_arg(args_copy, char*); arg != NULL; arg = va_arg(args_copy, char*)) {
		arg_count++;
	}
	va_end(args_copy);

	char *argv[arg_count+1];
	argv[0] = (char*)arg0;
	for (int i = 0; i < arg_count-1; i++) {
		char *arg = va_arg(args, char*);
		argv[i+1] = arg;
	}
	argv[arg_count] = NULL;

	return execve_hook(path, argv, environ);
}

int execv_hook(const char *path, char *const argv[])
{
	return execve_hook(path, argv, environ);
}

int execvP_hook(const char *file, const char *search_path, char *const argv[])
{
	__block bool execve_failed = false;
	int err = resolvePath(file, search_path, ^int(char *path) {
		(void)execve_hook(path, argv, environ);
		execve_failed = true;
		return 0;
	});
	if (!execve_failed) {
		errno = err;
	}
	return -1;
}

int execvp_hook(const char *name, char * const *argv)
{
	const char *path;
	/* Get the path we're searching. */
	if ((path = getenv("PATH")) == NULL)
		path = _PATH_DEFPATH;
	return execvP_hook(name, path, argv);
}


#include <sys/mount.h>
void* dlopen_hook(const char* path, int mode)
{
	if (path) {
		jbdswProcessLibrary(path);
	}
	
	void* callerAddress = __builtin_return_address(0);
    return dlopen_from(path, mode, callerAddress);
}

void* dlopen_from_hook(const char* path, int mode, void* addressInCaller)
{
	if (path) {
		jbdswProcessLibrary(path);
	}
	return dlopen_from(path, mode, addressInCaller);
}

void* dlopen_audited_hook(const char* path, int mode)
{
	if (path) {
		jbdswProcessLibrary(path);
	}
	return dlopen_audited(path, mode);
}

bool dlopen_preflight_hook(const char* path)
{
	if (path) {
		jbdswProcessLibrary(path);
	}
	return dlopen_preflight(path);
}

int sandbox_init_hook(const char *profile, uint64_t flags, char **errorbuf)
{
	int retval = sandbox_init(profile, flags, errorbuf);
	if (retval == 0) {
		unsandbox();
	}
	return retval;
}

int sandbox_init_with_parameters_hook(const char *profile, uint64_t flags, const char *const parameters[], char **errorbuf)
{
	int retval = sandbox_init_with_parameters(profile, flags, parameters, errorbuf);
	if (retval == 0) {
		unsandbox();
	}
	return retval;
}

int sandbox_init_with_extensions_hook(const char *profile, uint64_t flags, const char *const extensions[], char **errorbuf)
{
	int retval = sandbox_init_with_extensions(profile, flags, extensions, errorbuf);
	if (retval == 0) {
		unsandbox();
	}
	return retval;
}

int ptrace_hook(int request, pid_t pid, caddr_t addr, int data)
{
	int retval = ptrace(request, pid, addr, data);

	/*
		ptrace works on any process when the parent is unsandboxed,
		but when the victim process does not have the get-task-allow entitlement,
		it will fail to set the debug flags, therefore we patch ptrace to manually apply them
	*/
	if (retval == 0 && (request == PT_ATTACHEXC || request == PT_ATTACH)) {
		static int64_t (*__jbdProcSetDebugged)(pid_t pid);
		static dispatch_once_t onceToken;
		dispatch_once(&onceToken, ^{
			void *libjbHandle = dlopen(JB_ROOT_PATH("/basebin/libjailbreak.dylib"), RTLD_NOW);
			if (libjbHandle) {
				__jbdProcSetDebugged = dlsym(libjbHandle, "jbdProcSetDebugged");
			}
		});

		// we assume that when ptrace has worked, XPC to jailbreakd will also work
		if (__jbdProcSetDebugged) {
			__jbdProcSetDebugged(pid);
			__jbdProcSetDebugged(getpid());
		}
	}

	return retval;
}

void loadForkFix(void)
{
	if (swh_is_debugged) {
		static dispatch_once_t onceToken;
		dispatch_once (&onceToken, ^{
			// Once this process has wx_allowed, we need to load forkfix to ensure forking will work
			// Optimization: If the process cannot fork at all due to sandbox, we don't need to load forkfix
			if (sandbox_check(getpid(), "process-fork", SANDBOX_CHECK_NO_REPORT, NULL) == 0) {
				dlopen(JB_ROOT_PATH("/basebin/forkfix.dylib"), RTLD_NOW);
			}
		});
	}
}

pid_t fork_hook(void)
{
	loadForkFix();
	return fork();
}

pid_t vfork_hook(void)
{
	loadForkFix();
	return vfork();
}

pid_t forkpty_hook(int *amaster, char *name, struct termios *termp, struct winsize *winp)
{
	loadForkFix();
	return forkpty(amaster, name, termp, winp);
}

int daemon_hook(int __nochdir, int __noclose)
{
	loadForkFix();
	return daemon(__nochdir, __noclose);
}

bool shouldEnableTweaks(void)
{
	if (access(JB_ROOT_PATH("/basebin/.safe_mode"), F_OK) == 0) {
		return false;
	}

	char *tweaksDisabledEnv = getenv("DISABLE_TWEAKS");
	if (tweaksDisabledEnv) {
		if (!strcmp(tweaksDisabledEnv, "1")) {
			return false;
		}
	}

	const char *safeModeValue = getenv("_SafeMode");
	const char *msSafeModeValue = getenv("_MSSafeMode");
	if (safeModeValue) {
		if (!strcmp(safeModeValue, "1")) {
			return false;
		}
	}
	if (msSafeModeValue) {
		if (!strcmp(msSafeModeValue, "1")) {
			return false;
		}
	}

	const char *tweaksDisabledPathSuffixes[] = {
		// System binaries
		"/usr/libexec/xpcproxy",
		"/basebin/xpcproxy",

		// Dopamine app itself (jailbreak detection bypass tweaks can break it)
		"/Dopamine.app/Dopamine",
	};
	for (size_t i = 0; i < sizeof(tweaksDisabledPathSuffixes) / sizeof(const char*); i++)
	{
		if (stringEndsWith(gExecutablePath, tweaksDisabledPathSuffixes[i])) return false;
	}

	return true;
}

void applyKbdFix(void)
{
	// For whatever reason after SpringBoard has restarted, AutoFill and other stuff stops working
	// The fix is to always also restart the kbd daemon alongside SpringBoard
	// Seems to be something sandbox related where kbd doesn't have the right extensions until restarted
	killall("/System/Library/TextInput/kbd", false);
}



#include <pwd.h>
#include <libgen.h>
#include <stdio.h>
#include <libproc.h>
#include <libproc_private.h>
#include <sys/sysctl.h>

//some process may be killed by sandbox if call systme getppid()
pid_t __getppid()
{
    struct proc_bsdinfo procInfo;
	if (proc_pidinfo(getpid(), PROC_PIDTBSDINFO, 0, &procInfo, sizeof(procInfo)) <= 0) {
		return -1;
	}
    return procInfo.pbi_ppid;
}

static uid_t _CFGetSVUID(bool *successful) {
    uid_t uid = -1;
    struct kinfo_proc kinfo;
    u_int miblen = 4;
    size_t  len;
    int mib[miblen];
    int ret;
    mib[0] = CTL_KERN;
    mib[1] = KERN_PROC;
    mib[2] = KERN_PROC_PID;
    mib[3] = getpid();
    len = sizeof(struct kinfo_proc);
    ret = sysctl(mib, miblen, &kinfo, &len, NULL, 0);
    if (ret != 0) {
        uid = -1;
        *successful = false;
    } else {
        uid = kinfo.kp_eproc.e_pcred.p_svuid;
        *successful = true;
    }
    return uid;
}

bool _CFCanChangeEUIDs(void) {
    static bool canChangeEUIDs;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        uid_t euid = geteuid();
        uid_t uid = getuid();
        bool gotSVUID = false;
        uid_t svuid = _CFGetSVUID(&gotSVUID);
        canChangeEUIDs = (uid == 0 || uid != euid || svuid != euid || !gotSVUID);
    });
    return canChangeEUIDs;
}

void loadPathHook()
{
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
		int64_t debugErr = jbdswDebugMe();
		if (debugErr == 0) {
			void* roothidehooks = dlopen_hook(JB_ROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
			void (*pathhook)() = dlsym(roothidehooks, "pathhook");
			pathhook();
		}
	});
}

void redirect_path_env(const char* rootdir)
{
    //for now libSystem should be initlized, container should be set.

    char* homedir = NULL;

/* 
there is a bug in NSHomeDirectory,
if a containerized root process changes its uid/gid, 
NSHomeDirectory will return a home directory that it cannot access. (exclude NSTemporaryDirectory)
We just keep this bug:
*/
    if(!issetugid()) // issetugid() should always be false at this time. (but how about persona-mgmt? idk)
    {
        homedir = getenv("CFFIXED_USER_HOME");
        if(homedir)
        {
#define CONTAINER_PATH_PREFIX   "/private/var/mobile/Containers/Data/" // +/Application,PluginKitPlugin,InternalDaemon
            if(strncmp(homedir, CONTAINER_PATH_PREFIX, sizeof(CONTAINER_PATH_PREFIX)-1) == 0)
            {
                return; //containerized
            }
            else
            {
                homedir = NULL; //from parent, drop it
            }
        }
    }

    if(!homedir) {
        struct passwd* pwd = getpwuid(geteuid());
        if(pwd && pwd->pw_dir) {
            homedir = pwd->pw_dir;
        }
    }

    // if(!homedir) {
    //     //CFCopyHomeDirectoryURL does, but not for NSHomeDirectory
    //     homedir = getenv("HOME");
    // }

    if(!homedir) {
        homedir = "/var/empty";
    }

    char newhome[PATH_MAX]={0};
    snprintf(newhome,sizeof(newhome),"%s/%s",rootdir,homedir);
    setenv("CFFIXED_USER_HOME", newhome, 1);
}

void redirect_paths(const char* rootdir)
{
    do { // only for jb process because some system process may crash when chdir
        
        char executablePath[PATH_MAX]={0};
        uint32_t bufsize=sizeof(executablePath);
        if(_NSGetExecutablePath(executablePath, &bufsize) != 0)
            break;
        
        char realexepath[PATH_MAX];
        if(!realpath(executablePath, realexepath))
            break;
            
        char realjbroot[PATH_MAX];
        if(!realpath(rootdir, realjbroot))
            break;
        
        if(realjbroot[strlen(realjbroot)] != '/')
            strcat(realjbroot, "/");
        
        if(strncmp(realexepath, realjbroot, strlen(realjbroot)) != 0)
            break;

        //for jailbroken binaries
        redirect_path_env(rootdir);
		
		if(_CFCanChangeEUIDs()) {
			loadPathHook();
		}
    
        pid_t ppid = __getppid();
        assert(ppid > 0);
        if(ppid != 1)
            break;
        
        char pwd[PATH_MAX];
        if(getcwd(pwd, sizeof(pwd)) == NULL)
            break;
        if(strcmp(pwd, "/") != 0)
            break;
    
        assert(chdir(rootdir)==0);
        
    } while(0);
}

//export for PatchLoader
__attribute__((visibility("default"))) int PLRequiredJIT() {
	return jbdswDebugMe();
}

char HOOK_DYLIB_PATH[PATH_MAX] = {0}; //"/usr/lib/systemhook.dylib"
__attribute__((constructor)) static void initializer(void)
{
	JB_SandboxExtensions = strdup(getenv("JB_SANDBOX_EXTENSIONS"));
	unsetenv("JB_SANDBOX_EXTENSIONS");
	JB_RootPath = strdup(getenv("JB_ROOT_PATH"));
	unsetenv("JB_ROOT_PATH");

	JBRAND = strdup(getenv("JBRAND"));
	JBROOT = strdup(getenv("JBROOT"));

	struct dl_info di={0};
    dladdr((void*)initializer, &di);
	strncpy(HOOK_DYLIB_PATH, di.dli_fname, sizeof(HOOK_DYLIB_PATH));

	if (!strcmp(getenv("DYLD_INSERT_LIBRARIES"), HOOK_DYLIB_PATH)) {
		// Unset DYLD_INSERT_LIBRARIES, but only if we are the only thing contained in it
		unsetenv("DYLD_INSERT_LIBRARIES");
	}

	unsandbox();
	loadExecutablePath();

	if(stringEndsWith(gExecutablePath, "/Dopamine.app/Dopamine")) {
		char roothidefile[PATH_MAX];
		snprintf(roothidefile, sizeof(roothidefile), "%s.roothide",gExecutablePath);
		if(access(roothidefile, F_OK) != 0) {
			exit(0);
		}
	}

	struct stat sb;
	if(stat(gExecutablePath, &sb) == 0) {
		if (S_ISREG(sb.st_mode) && (sb.st_mode & (S_ISUID | S_ISGID))) {
			jbdswFixSetuid();
		}
	}

	redirect_paths(JBROOT);

	dlopen_hook(JB_ROOT_PATH("/usr/lib/roothideinit.dylib"), RTLD_NOW);

	if (gExecutablePath) 
	{
		if (strcmp(gExecutablePath, "/System/Library/CoreServices/SpringBoard.app/SpringBoard") == 0) {
			applyKbdFix();
		}
		
		if (strcmp(gExecutablePath, "/usr/sbin/cfprefsd") == 0
		|| strcmp(gExecutablePath, "/usr/libexec/lsd") == 0
		|| strcmp(gExecutablePath, "/System/Library/CoreServices/SpringBoard.app/SpringBoard") == 0) 
		{
			int64_t debugErr = jbdswDebugMe();
			if (debugErr == 0) {
				void* d = dlopen_hook(JB_ROOT_PATH("/basebin/roothidehooks.dylib"), RTLD_NOW);
			}
		}
		else if (strcmp(gExecutablePath, "/usr/libexec/watchdogd") == 0) {
			int64_t debugErr = jbdswDebugMe();
			if (debugErr == 0) {
				dlopen_hook(JB_ROOT_PATH("/basebin/watchdoghook.dylib"), RTLD_NOW);
			}
		}
	}

	//load first
	dlopen_hook(JB_ROOT_PATH("/usr/lib/roothidepatch.dylib"), RTLD_NOW); //need jit

	if (shouldEnableTweaks()) {
		int64_t debugErr = jbdswDebugMe();
		if (debugErr == 0) {
			const char *tweakLoaderPath = JB_ROOT_PATH("/usr/lib/TweakLoader.dylib");
			if(access(tweakLoaderPath, F_OK) == 0)
			{
				void *tweakLoaderHandle = dlopen_hook(tweakLoaderPath, RTLD_NOW);
				if (tweakLoaderHandle != NULL) {
					//dlclose(tweakLoaderHandle); //will hide TweakLoader module
				}
			}
		}
	}

	//freeExecutablePath();
	
	//unset these to prevent from using by third-party
	// unsetenv("JBRAND");
	// unsetenv("JBROOT");
	// some tweaks use NSTask to call command so that can't inject systemhook
	// so we keep these to for now
}


#define RB2_USERREBOOT (0x2000000000000000llu)
#define RB2_OBLITERATE (0x4000000000000000llu)
#define RB2_FULLREBOOT (0x8000000000000000llu)
#define ITHINK_HALT    (0x8000000000000008llu)
int reboot3(uint64_t how, uint64_t unk);
int reboot3_hook(uint64_t how, uint64_t unk)
{
	if(how == RB2_USERREBOOT) {
		return jbdswRebootUserspace();
	}
	return reboot3(how, unk);
}

DYLD_INTERPOSE(posix_spawn_hook, posix_spawn)
DYLD_INTERPOSE(posix_spawnp_hook, posix_spawnp)
DYLD_INTERPOSE(execve_hook, execve)
DYLD_INTERPOSE(execle_hook, execle)
DYLD_INTERPOSE(execlp_hook, execlp)
DYLD_INTERPOSE(execv_hook, execv)
DYLD_INTERPOSE(execl_hook, execl)
DYLD_INTERPOSE(execvp_hook, execvp)
DYLD_INTERPOSE(execvP_hook, execvP)
DYLD_INTERPOSE(dlopen_hook, dlopen)
DYLD_INTERPOSE(dlopen_from_hook, dlopen_from)
DYLD_INTERPOSE(dlopen_audited_hook, dlopen_audited)
DYLD_INTERPOSE(dlopen_preflight_hook, dlopen_preflight)
DYLD_INTERPOSE(sandbox_init_hook, sandbox_init)
DYLD_INTERPOSE(sandbox_init_with_parameters_hook, sandbox_init_with_parameters)
DYLD_INTERPOSE(sandbox_init_with_extensions_hook, sandbox_init_with_extensions)
DYLD_INTERPOSE(ptrace_hook, ptrace)
DYLD_INTERPOSE(fork_hook, fork)
DYLD_INTERPOSE(vfork_hook, vfork)
DYLD_INTERPOSE(forkpty_hook, forkpty)
DYLD_INTERPOSE(daemon_hook, daemon)
DYLD_INTERPOSE(reboot3_hook, reboot3)
