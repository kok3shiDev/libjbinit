/*
 * bakera1n - dyld_ramdisk.c
 *
 * Copyright (c) 2022 - 2023 tihmstar
 * Copyright (c) 2023 dora2ios
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 */

#include <stdint.h>
#include <plog.h>

#include "printf.h"
#include "dyld_utils.h"

#include "../launchdhook/build/haxx_dylib.h"
#include "../launchdhook/build/injector.h"
#include "../payload/haxx.h"
#include "cfprefsdhook_dylib.h"
#include "libellekit_dylib.h"

asm(
    ".globl __dyld_start    \n"
    ".align 4               \n"
    "__dyld_start:          \n"
    "movn x8, #0xf          \n"
    "mov  x7, sp            \n"
    "and  x7, x7, x8        \n"
    "mov  sp, x7            \n"
    "bl   _main             \n"
    "movz x16, #0x1         \n"
    "svc  #0x80             \n"
    );

static checkrain_option_t pflags;
static char *root_device = NULL;
static int isOS = 0;
static char statbuf[0x400];

static inline __attribute__((always_inline)) int checkrain_option_enabled(checkrain_option_t flags, checkrain_option_t opt)
{
    if(flags == checkrain_option_failure)
    {
        switch(opt)
        {
            case checkrain_option_safemode:
                return 1;
            default:
                return 0;
        }
    }
    return (flags & opt) != 0;
}

static inline __attribute__((always_inline)) int getFlags(void)
{
    uint32_t err = 0;
    
    size_t sz = 0;
    struct kerninfo info;
    int fd = open("/dev/rmd0", O_RDONLY|O_RDWR, 0);
    if (fd >= 0x1)
    {
        read(fd, &sz, 4);
        lseek(fd, (long)(sz), SEEK_SET);
        if(read(fd, &info, sizeof(struct kerninfo)) == sizeof(struct kerninfo))
        {
            pflags = info.flags;
            LOG("got flags: %d from stage1", pflags);
            err = 0;
        } else
        {
            ERR("Read kinfo failed");
            err = -1;
        }
        close(fd);
    }
    else
    {
        ERR("Open rd failed");
        err = -1;
    }
    
    return err;
}

int lz4dec_dyld(const void *inbuf, uint32_t len, void** outbuf, uint32_t* outlen);

static inline __attribute__((always_inline)) int main2(void)
{
    
    LOG("Remounting fs");
    {
        char *path = ROOTFS_RAMDISK;
        if (mount("apfs", "/", MNT_UPDATE, &path))
        {
            FATAL("Failed to remount ramdisk");
            goto fatal_err;
        }
    }
    
    LOG("Unlinking fakedyld");
    {
        unlink(CUSTOM_DYLD_PATH);
        if(!stat(CUSTOM_DYLD_PATH, statbuf))
        {
            FATAL("Why does that %s exist!?", CUSTOM_DYLD_PATH);
            goto fatal_err;
        }
    }
    
    LOG("Remounting fs");
    {
        char *path = ROOTFS_RAMDISK;
        if (mount("apfs", "/", MNT_UPDATE | MNT_RDONLY, &path))
        {
            FATAL("Failed to remount ramdisk");
            goto fatal_err;
        }
    }
    
    int mntflag = MOUNT_WITH_SNAPSHOT;
    
    {
        char *mntpath = "/";
        LOG("Mounting rootfs to %s", mntpath);
        
        int err = 0;
        char buf[0x100];
        struct mounarg {
            char *path;
            uint64_t _null;
            uint64_t mountAsRaw;
            uint32_t _pad;
            char snapshot[0x100];
        } arg = {
            root_device,
            0,
            mntflag,
            0,
        };
        
    retry_rootfs_mount:
        err = mount("apfs", mntpath, MNT_RDONLY, &arg);
        if (err)
        {
            ERR("Failed to mount rootfs (%d)", err);
            sleep(1);
        }
        
        if (stat("/private/", statbuf))
        {
            ERR("Failed to find directory, retry.");
            sleep(1);
            goto retry_rootfs_mount;
        }
        
        LOG("Mounting devfs");
        {
            if (mount_devfs("/dev"))
            {
                FATAL("Failed to mount devfs");
                goto fatal_err;
            }
        }
    }
    
    {
        LOG("Mounting tmpfs");
        struct tmpfs_mountarg
        {
            uint64_t max_pages;
            uint64_t max_nodes;
            uint8_t case_insensitive;
        };
        
        int64_t pagesize;
        unsigned long pagesize_len = sizeof(pagesize);
        if (sys_sysctlbyname("hw.pagesize", sizeof("hw.pagesize"), &pagesize, &pagesize_len, NULL, 0))
        {
            FATAL("Failed to get pagesize");
            goto fatal_err;
        }
        
        struct tmpfs_mountarg arg = {.max_pages = (1887436 / pagesize), .max_nodes = UINT8_MAX, .case_insensitive = 0};
        if (mount("tmpfs", "/cores", 0, &arg))
        {
            FATAL("Failed to mount tmpfs onto /cores");
            goto fatal_err;
        }
    }
    
    {
        if(mkdir("/cores/binpack", 0755))
        {
            FATAL("Failed to make directory %s", "/cores/binpack");
            goto fatal_err;
        }
        if (stat("/cores/binpack", statbuf))
        {
            FATAL("Failed to stat directory %s", "/cores/binpack");
            goto fatal_err;
        }
    }
    
    // lz4dec
    void *haxxDylibBuf = NULL;
    uint32_t haxxDylibLen = 0;
    if(lz4dec_dyld(haxx_dylib, haxx_dylib_len, &haxxDylibBuf, &haxxDylibLen))
    {
        FATAL("Failed to lz4dec");
        goto fatal_err;
    }
    
    void *haxxBinBuf = NULL;
    uint32_t haxxBinLen = 0;
    if(lz4dec_dyld(haxx, haxx_len, &haxxBinBuf, &haxxBinLen))
    {
        FATAL("Failed to lz4dec");
        goto fatal_err;
    }
    
    void *cfprefsdHookBuf = NULL;
    uint32_t cfprefsdHookLen = 0;
    if(lz4dec_dyld(cfprefsdhook_dylib, cfprefsdhook_dylib_len, &cfprefsdHookBuf, &cfprefsdHookLen))
    {
        FATAL("Failed to lz4dec");
        goto fatal_err;
    }
    
    void *injectorBuf = NULL;
    uint32_t injectorLen = 0;
    if(lz4dec_dyld(injector, injector_len, &injectorBuf, &injectorLen))
    {
        FATAL("Failed to lz4dec");
        goto fatal_err;
    }
    
    void *ellekitBuf = NULL;
    uint32_t ellekitLen = 0;
    if(lz4dec_dyld(libellekit_dylib, libellekit_dylib_len, &ellekitBuf, &ellekitLen))
    {
        FATAL("Failed to lz4dec");
        goto fatal_err;
    }
    
    
    // deploy
    if(deploy_file_from_memory(LIBRARY_PATH, haxxDylibBuf, haxxDylibLen))
    {
        FATAL("Failed to open %s", LIBRARY_PATH);
        goto fatal_err;
    }
    
    if(deploy_file_from_memory(PAYLOAD_PATH, haxxBinBuf, haxxBinLen))
    {
        FATAL("Failed to open %s", LIBRARY_PATH);
        goto fatal_err;
    }
    
    if(deploy_file_from_memory(CFPREFSD_HOOK, cfprefsdHookBuf, cfprefsdHookLen))
    {
        FATAL("Failed to open %s", CFPREFSD_HOOK);
        goto fatal_err;
    }
    
    if(deploy_file_from_memory(INJECTOR_PATH, injectorBuf, injectorLen))
    {
        FATAL("Failed to open %s", INJECTOR_PATH);
        goto fatal_err;
    }
    
    if(deploy_file_from_memory(ELLEKIT_LIB, ellekitBuf, ellekitLen))
    {
        FATAL("Failed to open %s", ELLEKIT_LIB);
        goto fatal_err;
    }
    
    
    // munmap
    if(munmap(haxxDylibBuf, (haxxDylibLen & ~0x3fff) + 0x4000))
    {
        FATAL("Failed to munmap");
        goto fatal_err;
    }
    
    if(munmap(haxxBinBuf, (haxxBinLen & ~0x3fff) + 0x4000))
    {
        FATAL("Failed to munmap");
        goto fatal_err;
    }
    
    if(munmap(cfprefsdHookBuf, (cfprefsdHookLen & ~0x3fff) + 0x4000))
    {
        FATAL("Failed to munmap");
        goto fatal_err;
    }
    
    if(munmap(injectorBuf, (injectorLen & ~0x3fff) + 0x4000))
    {
        FATAL("Failed to munmap");
        goto fatal_err;
    }
    
    if(munmap(ellekitBuf, (ellekitLen & ~0x3fff) + 0x4000))
    {
        FATAL("Failed to munmap");
        goto fatal_err;
    }
    
    void *data = mmap(NULL, 0x4000, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    DEVLOG("data: 0x%016llx", data);
    if (data == (void*)-1)
    {
        FATAL("Failed to mmap");
        goto fatal_err;
    }
    
    
    {
        if (stat(LAUNCHD_PATH, statbuf))
        {
            FATAL("%s: No such file or directory", LAUNCHD_PATH);
            goto fatal_err;
        }
        if (stat(PAYLOAD_PATH, statbuf))
        {
            FATAL("%s: No such file or directory", PAYLOAD_PATH);
            goto fatal_err;
        }
        if (stat(LIBRARY_PATH, statbuf))
        {
            FATAL("%s: No such file or directory", PAYLOAD_PATH);
            goto fatal_err;
        }
        if (stat(CFPREFSD_HOOK, statbuf))
        {
            FATAL("%s: No such file or directory", CFPREFSD_HOOK);
            goto fatal_err;
        }
        if (stat(ELLEKIT_LIB, statbuf))
        {
            FATAL("%s: No such file or directory", ELLEKIT_LIB);
            goto fatal_err;
        }
    }
    
    /*
     Launchd doesn't like it when the console is open already
     */
    
    for (size_t i = 0; i < 10; i++)
        close(i);
    
    int err = 0;
    {
        char **argv = (char **)data;
        char **envp = argv+2;
        char *strbuf = (char*)(envp+2);
        argv[0] = strbuf;
        argv[1] = NULL;
        memcpy(strbuf, LAUNCHD_PATH, sizeof(LAUNCHD_PATH));
        strbuf += sizeof(LAUNCHD_PATH);
        envp[0] = strbuf;
        envp[1] = NULL;
        
        char dyld_insert_libs[] = "DYLD_INSERT_LIBRARIES";
        char dylibs[] = LIBRARY_PATH;
        uint8_t eqBuf = 0x3D;
        
        memcpy(strbuf, dyld_insert_libs, sizeof(dyld_insert_libs));
        memcpy(strbuf+sizeof(dyld_insert_libs)-1, &eqBuf, 1);
        memcpy(strbuf+sizeof(dyld_insert_libs)-1+1, dylibs, sizeof(dylibs));
        
        err = execve(argv[0], argv, envp);
    }
    
    if (err) {
        FATAL("Failed to execve (%d)", err);
        goto fatal_err;
    }
    
fatal_err:
    FATAL("see you my friend...");
    spin();
    
    return 0;
}

int main(void)
{
    int console = open("/dev/console", O_RDWR, 0);
    sys_dup2(console, 0);
    sys_dup2(console, 1);
    sys_dup2(console, 2);
    
    printf("#==================\n");
    printf("#\n");
    printf("# bakera1n loader %s\n", VERSION);
    printf("#\n");
    printf("# (c) 2023 kok3shiDev\n");
    printf("#==================\n");
    
    LOG("Checking rootfs");
    {
        while ((stat(ROOTFS_IOS16, statbuf)) &&
               (stat(ROOTFS_IOS15, statbuf)))
        {
            LOG("Waiting for roots...");
            sleep(1);
        }
    }
    
    if(stat(ROOTFS_IOS15, statbuf))
    {
        root_device = ROOTFS_IOS16;
        isOS = IS_IOS16;
    }
    else
    {
        root_device = ROOTFS_IOS15;
        isOS = IS_IOS15;
    }
    
    if(!root_device)
    {
        FATAL("Failed to get root_device");
        goto fatal_err;
    }
    
    LOG("Got root_device: %s", root_device);
    
    if(getFlags())
    {
        pflags = checkrain_option_failure;
    }
    
    {
        // rootless without bindfs
        return main2();
    }
    
fatal_err:
    FATAL("see you my friend...");
    spin();
    
    return 0;
}
