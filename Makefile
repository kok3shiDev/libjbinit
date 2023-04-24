CC		=	xcrun -sdk iphoneos clang
ARCH	+=	-arch arm64
LIBS	+=	-framework Foundation

DYLD_FLAGS	+=	-e__dyld_start -Wl,-dylinker -Wl,-dylinker_install_name,/usr/lib/dyld -nostdlib -static -Wl,-fatal_warnings -Wl,-dead_strip -Wl,-Z --target=arm64-apple-ios12.0 -std=gnu17 -flto -ffreestanding -U__nonnull -nostdlibinc -fno-stack-protector

DYLIB_FLAGS	+=	-shared
DEBUG_FLAGS	+=	-DDEVBUILD=1
ROOTFUL_FLAGS	+=	-DROOTFULL=1

.PHONY: all clean

all:
	# rootless dylib
	$(CC) $(ARCH) $(DYLIB_FLAGS) $(DEBUG_FLAGS) $(LIBS) libpayload.m -o build/haxx.dylib
	ldid -S build/haxx.dylib
	cd build && xxd -i haxx.dylib > haxx_dylib.h
	
	# fake dyld
	$(CC) $(DYLD_FLAGS) $(DEBUG_FLAGS) $(DEVFLAG) -Iinclude/ dyld_ramdisk.c printf.c dyld_utils.c -o build/com.apple.dyld
	strip build/com.apple.dyld
	ldid -S build/com.apple.dyld
	
clean:
	rm -f build/haxx.dylib
	rm -f build/haxx_dylib.h
	rm -f build/com.apple.dyld
