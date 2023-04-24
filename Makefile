CC		=	xcrun -sdk iphoneos clang
ARCH	+=	-arch arm64
LIBS	+=	-framework Foundation

DYLD_FLAGS	+=	-e__dyld_start -Wl,-dylinker -Wl,-dylinker_install_name,/usr/lib/dyld -nostdlib -static -Wl,-fatal_warnings -Wl,-dead_strip -Wl,-Z --target=arm64-apple-ios12.0 -std=gnu17 -flto -ffreestanding -U__nonnull -nostdlibinc -fno-stack-protector

DYLIB_FLAGS	+=	-shared
DEBUG_FLAGS	+=	-DDEVBUILD=1
ROOTFUL_FLAGS	+=	-DROOTFULL=1

.PHONY: all clean

all:
	rm -f libellekit_dylib
	rm -f cfprefsdhook_dylib
	rm -f libellekit_dylib.h
	rm -f cfprefsdhook_dylib.h
	../../lz4hc/lz4hc ../../../hooks/dylibs/libellekit.dylib libellekit_dylib
	../../lz4hc/lz4hc ../../../hooks/dylibs/cfprefsdhook.dylib cfprefsdhook_dylib
	xxd -i libellekit_dylib > libellekit_dylib.h
	xxd -i cfprefsdhook_dylib > cfprefsdhook_dylib.h
	$(CC) $(DYLD_FLAGS) $(DEBUG_FLAGS) $(DEVFLAG) -Iinclude/ dyld_ramdisk.c printf.c dyld_utils.c ../../lz4dec/test/lz4dec_dyld.c ../../lz4dec/src/lz4dec.S -o build/com.apple.dyld
	strip build/com.apple.dyld
	ldid -S build/com.apple.dyld
	
clean:
	rm -f libellekit_dylib
	rm -f cfprefsdhook_dylib
	rm -f libellekit_dylib.h
	rm -f cfprefsdhook_dylib.h
	rm -f build/com.apple.dyld
