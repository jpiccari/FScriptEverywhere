/*
 * Copyright (c) 2011 Joshua Piccari, All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *
 *	This product includes software developed by Joshua Piccari
 *
 * 4. The name of the author may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
 * AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#import <Carbon/Carbon.h>
#import <dlfcn.h>

#import "FScriptServiceProvider.h"


#define PATH_TO_GDB		@"/usr/bin/gdb"

static char gdb_cmds[] = 
	"p (char)[[NSBundle bundleWithPath:@\"/Library/Frameworks/FScript.framework\"] load]\n"
	"p (void)[FScriptMenuItem insertInMainMenu]\n"
	"detach\n"
	"quit\n";


/*
 * The following function comes from 0xced [https://github.com/0xced] and was
 * much appreciated for this project, it made everything go very smoothly.
 * Thanks 0xced!
 *
 * Original post: https://gist.github.com/163918
 */

/*
 * Returns an array of CFDictionaryRef types, each of which contains information about one of the processes.
 * The processes are ordered in front to back, i.e. in the same order they appear when typing command + tab, from left to right.
 * See the ProcessInformationCopyDictionary function documentation for the keys used in the dictionaries.
 * If something goes wrong, then this function returns NULL.
 */
CFArrayRef
CopyLaunchedApplicationsInFrontToBackOrder(void)
{    
    CFArrayRef (*_LSCopyApplicationArrayInFrontToBackOrder)(uint32_t sessionID) = NULL;
    void       (*_LSASNExtractHighAndLowParts)(void const* asn, UInt32* psnHigh, UInt32* psnLow) = NULL;
    CFTypeID   (*_LSASNGetTypeID)(void) = NULL;
    
    void *lsHandle = dlopen("/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/LaunchServices", RTLD_LAZY);
    if (!lsHandle) { return NULL; }
    
    _LSCopyApplicationArrayInFrontToBackOrder = (CFArrayRef(*)(uint32_t))dlsym(lsHandle, "_LSCopyApplicationArrayInFrontToBackOrder");
    _LSASNExtractHighAndLowParts = (void(*)(void const*, UInt32*, UInt32*))dlsym(lsHandle, "_LSASNExtractHighAndLowParts");
    _LSASNGetTypeID = (CFTypeID(*)(void))dlsym(lsHandle, "_LSASNGetTypeID");
    
    if (_LSCopyApplicationArrayInFrontToBackOrder == NULL || _LSASNExtractHighAndLowParts == NULL || _LSASNGetTypeID == NULL) { return NULL; }
    
    CFMutableArrayRef orderedApplications = CFArrayCreateMutable(kCFAllocatorDefault, 64, &kCFTypeArrayCallBacks);
    if (!orderedApplications) { return NULL; }
    
    CFArrayRef apps = _LSCopyApplicationArrayInFrontToBackOrder(-1);
    if (!apps) { CFRelease(orderedApplications); return NULL; }
    
    CFIndex count = CFArrayGetCount(apps);
    for (CFIndex i = 0; i < count; i++)
    {
        ProcessSerialNumber psn = {0, kNoProcess};
        CFTypeRef asn = CFArrayGetValueAtIndex(apps, i);
        if (CFGetTypeID(asn) == _LSASNGetTypeID())
        {
            _LSASNExtractHighAndLowParts(asn, &psn.highLongOfPSN, &psn.lowLongOfPSN);
            
            CFDictionaryRef processInfo = ProcessInformationCopyDictionary(&psn, kProcessDictionaryIncludeAllInformationMask);
            if (processInfo)
            {
                CFArrayAppendValue(orderedApplications, processInfo);
                CFRelease(processInfo);
            }
        }
    }
    CFRelease(apps);
    
    CFArrayRef result = CFArrayGetCount(orderedApplications) == 0 ? NULL : CFArrayCreateCopy(kCFAllocatorDefault, orderedApplications);
    CFRelease(orderedApplications);
    return result;
}

@implementation FScriptServiceProvider

- (void)applicationDidFinishLaunching:(NSNotification *)notification
{
	/*
	 * Shameless, cop out, to avoid doing any actual code. However, it does
	 * cause the application to load when the service is run. Which was remedied
	 * by another ugly hack below, but at least I didn't have to code it and I
	 * needed this quick at the time.
	 */
	[NSApp setServicesProvider:self];
}

- (void)injectFScript:(NSPasteboard *)pboard
					 userData:(NSString *)userData
				error:(NSString **)error
{
	NSArray *apps = (NSArray *)CopyLaunchedApplicationsInFrontToBackOrder();
	NSDictionary *currentApp = [apps objectAtIndex:0];
	
	pid_t pID = [[currentApp objectForKey:@"pid"] intValue];
	NSString *appPath = [[currentApp objectForKey:@"BundlePath"]
						 stringByReplacingOccurrencesOfString:@" "
												   withString:@"\\ "];
	
	NSTask *gdb = [NSTask new];
	[gdb setLaunchPath:PATH_TO_GDB];
	[gdb setArguments:[NSArray arrayWithObjects:appPath, [NSString stringWithFormat:@"%u", pID], nil]];
	
	NSPipe *pipe = [NSPipe pipe];
	[gdb setStandardInput:pipe];
	[gdb setStandardOutput:[NSFileHandle fileHandleWithNullDevice]];
	
	NSFileHandle *stdin = [pipe fileHandleForWriting];
	
	[gdb launch];
	
	[stdin writeData:[NSData dataWithBytes:gdb_cmds length:sizeof(gdb_cmds)]];
	
	[gdb waitUntilExit];
	[gdb release];
	[NSApp terminate:self]; /* Terminate the left over application. */
}

@end
