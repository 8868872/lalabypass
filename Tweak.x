// lalabypass —— 货拉拉司机端 越狱环境屏蔽（roothide / rootless）
// 纯 Logos 实现，不依赖 substrate.h，编译成功率高

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <CoreLocation/CoreLocation.h>
#import <objc/runtime.h>
#import <sys/stat.h>
#import <errno.h>
#import <stdio.h>
#import <stdlib.h>
#import <string.h>

// dyld 私有接口，需手动声明
extern const char *_dyld_get_image_name(uint32_t image_index);
extern uint32_t _dyld_image_count(void);

// ── 私有类声明（Logos 需要） ──
@interface LSApplicationWorkspace : NSObject
+ (instancetype)defaultWorkspace;
- (NSArray *)allInstalledApplications;
- (NSArray *)installedApplications;
@end

@interface CLLocation (YGExtra)
- (BOOL)isSimulatedBySoftware;
- (BOOL)_isSimulatedBySoftware;
- (BOOL)isFromMockProvider;
@end

// ── 判定表 ──
static BOOL YGBadPath(const char *p) {
    if (!p) return NO;
    NSString *s = [NSString stringWithUTF8String:p];
    if (!s) return NO;
    if ([s rangeOfString:@".jbroot-"].location != NSNotFound) return YES;

    static NSArray *pre = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        pre = @[@"/var/jb", @"/private/var/jb", @"/private/preboot",
                @"/usr/sbin/sshd", @"/usr/bin/ssh", @"/usr/bin/scp",
                @"/bin/bash", @"/usr/bin/cycript", @"/usr/lib/libcycript",
                @"/Applications/Cydia.app", @"/Library/MobileSubstrate",
                @"/usr/lib/libsubstrate", @"/usr/lib/libhooker",
                @"/usr/lib/libellekit", @"/etc/apt", @"/private/etc/apt",
                @"/private/var/lib/dpkg", @"/var/lib/cydia", @"/private/var/stash",
                @"/var/cache/apt", @"/usr/libexec/cydia", @"/usr/bin/apt",
                @"/usr/bin/dpkg", @"/usr/sbin/inetd"];
    });
    for (NSString *x in pre) {
        if ([s hasPrefix:x]) return YES;
    }
    return NO;
}

static BOOL YGBadBundle(NSString *bid) {
    if (!bid || bid.length == 0) return NO;
    static NSArray *pre = nil;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        pre = @[@"com.opa334.dopamine", @"com.opa334.trollstore",
                @"com.opa334.choicy", @"org.coolstar.sileostore",
                @"com.roothide.", @"com.son3ra1n.", @"xc.lzsxcl.",
                @"signall.nuosike.", @"com.ex.substitute", @"com.saurik.",
                @"com.bingner.", @"me.trollstore", @"com.opa334.trollstorehelper"];
    });
    NSString *low = bid.lowercaseString;
    for (NSString *x in pre) {
        if ([low hasPrefix:x]) return YES;
    }
    return NO;
}

static BOOL YGBadImage(const char *n) {
    if (!n) return NO;
    NSString *s = [NSString stringWithUTF8String:n].lowercaseString;
    if (!s) return NO;
    return [s containsString:@"frida"] || [s containsString:@"ellekit"] ||
           [s containsString:@"libhooker"] || [s containsString:@"substrate"] ||
           [s containsString:@"substitute"] || [s containsString:@"cycript"] ||
           [s containsString:@"jbroot"] || [s containsString:@"lalabypass"];
}

// ═══════════ ① 文件层 ═══════════
%hookf(int, access, const char *path, int mode) {
    if (YGBadPath(path)) { errno = ENOENT; return -1; }
    return %orig;
}

%hookf(int, stat, const char *path, struct stat *buf) {
    if (YGBadPath(path)) { errno = ENOENT; return -1; }
    return %orig;
}

%hookf(int, lstat, const char *path, struct stat *buf) {
    if (YGBadPath(path)) { errno = ENOENT; return -1; }
    return %orig;
}

%hookf(FILE *, fopen, const char *path, const char *mode) {
    if (YGBadPath(path)) { errno = ENOENT; return NULL; }
    return %orig;
}

%hook NSFileManager
- (BOOL)fileExistsAtPath:(NSString *)path {
    if (path && YGBadPath(path.UTF8String)) return NO;
    return %orig;
}
- (BOOL)fileExistsAtPath:(NSString *)path isDirectory:(BOOL *)isDir {
    if (path && YGBadPath(path.UTF8String)) { if (isDir) *isDir = NO; return NO; }
    return %orig;
}
%end

// ═══════════ ② 镜像层 ═══════════
%hookf(const char *, _dyld_get_image_name, uint32_t idx) {
    const char *n = %orig;
    if (YGBadImage(n)) return "/usr/lib/libobjc.A.dylib";
    return n;
}

// ═══════════ ③ 应用列表 ═══════════
%hook LSApplicationWorkspace
- (NSArray *)allInstalledApplications {
    NSArray *arr = %orig;
    if (!arr) return arr;
    NSMutableArray *keep = [NSMutableArray arrayWithCapacity:arr.count];
    for (id proxy in arr) {
        NSString *bid = nil;
        @try { bid = [proxy bundleIdentifier]; } @catch (__unused NSException *e) {}
        NSString *path = nil;
        @try { path = [[proxy bundleURL] path]; } @catch (__unused NSException *e) {}

        if (YGBadBundle(bid)) {
            NSLog(@"[lalabypass] hide app %@", bid);
            continue;
        }
        if (path && [path rangeOfString:@".jbroot-"].location != NSNotFound) {
            NSLog(@"[lalabypass] hide app %@ (%@)", bid, path);
            continue;
        }
        [keep addObject:proxy];
    }
    return keep;
}
- (NSArray *)installedApplications {
    return [self allInstalledApplications];
}
%end

// ═══════════ ⑥ URL scheme ═══════════
%hook UIApplication
- (BOOL)canOpenURL:(NSURL *)url {
    NSString *s = url.absoluteString.lowercaseString;
    NSArray *bad = @[@"cydia:", @"sileo:", @"zebra:", @"installer:",
                     @"filza:", @"ssh:", @"apt:", @"undecimus:", @"trollstore:"];
    for (NSString *p in bad) {
        if ([s hasPrefix:p]) return NO;
    }
    return %orig;
}
%end

// ═══════════ ⑦ 定位 mock ═══════════
%hook CLLocation
- (BOOL)isSimulatedBySoftware { return NO; }
- (BOOL)_isSimulatedBySoftware { return NO; }
- (BOOL)isFromMockProvider { return NO; }
%end

// ═══════════ ⑧ 环境变量 ═══════════
%hookf(char *, getenv, const char *name) {
    if (name) {
        NSString *k = [NSString stringWithUTF8String:name];
        if ([k containsString:@"DYLD_INSERT_LIBRARIES"] ||
            [k containsString:@"DYLD_FORCE_FLAT_NAMESPACE"] ||
            [k containsString:@"JAILBREAK"]) {
            return NULL;
        }
    }
    return %orig;
}

// ═══════════ 入口 ═══════════
%ctor {
    @autoreleasepool {
        NSLog(@"[lalabypass] loaded into %@",
              [[NSBundle mainBundle] bundleIdentifier]);
    }
}
