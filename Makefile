.PHONY: all clean

# Updated for A7-A10X. 
TARGET       = kloader64
ENTITLEMENTS = entitlements.plist
SIGN         = ldid

# We need optimization and to silence deprecated warnings since we are using 
# older IOKit power management headers for the sleep trampoline.
FLAGS        = -framework IOKit -framework CoreFoundation -Wall -O2 -Wno-deprecated-declarations

# Apple uses clang; forcing the iphoneos sdk path ensures we don't link macOS headers by mistake.
IGCC         ?= xcrun -sdk iphoneos clang 

# A7-A10X requires arm64. I left armv7 in so it builds a fat binary, 
# ensuring maximum compatibility across your test devices.
ARCH         ?= -arch arm64 -arch armv7
AARCH        = $(shell arch)
UNAME        = $(shell uname -s)

all: $(TARGET)

$(TARGET): *.c
	@echo "[INFO]: Compiling $(TARGET) for untethered dualboot..."
	$(IGCC) $(ARCH) -o $@ $(FLAGS) $^
	@echo "[INFO]: Injecting tfp0 and AMFI-bypass entitlements..."
	$(SIGN) -S$(ENTITLEMENTS) $@
	@echo "[OK]: Compiled and signed $(TARGET) flawlessly on $(UNAME) $(AARCH)."

clean:
	rm -f $(TARGET)
