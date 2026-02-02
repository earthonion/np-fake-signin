PS4_HOST ?= ps4
PS4_PORT ?= 9021

# Username to patch into dat files (override with: make all NP_USER=MyUser)
NP_USER ?= User1

# Top-level targets: build both platforms
all: datfiles headers build-ps4 build-ps5

build-ps4:
	$(MAKE) PLATFORM=ps4 signin-elf

build-ps5:
	$(MAKE) PLATFORM=ps5 signin-elf

clean:
	rm -f bin/np-fake-signin-ps4.elf bin/np-fake-signin-ps5.elf
	rm -f include/auth_dat.h include/account_dat.h include/token_dat.h include/config_dat.h
	rm -f output/*.dat

# --- Per-platform build (called recursively) ---

ifdef PLATFORM

ifeq ($(PLATFORM),ps5)
    ifdef PS5_PAYLOAD_SDK
        include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
    else
        $(error PS5_PAYLOAD_SDK is undefined)
    endif
    PLATFORM_CFLAGS := -DPS5
else
    ifdef PS4_PAYLOAD_SDK
        include $(PS4_PAYLOAD_SDK)/toolchain/orbis.mk
    else
        $(error PS4_PAYLOAD_SDK is undefined)
    endif
    PLATFORM_CFLAGS :=
endif

CFLAGS := -Wall $(PLATFORM_CFLAGS)
LDFLAGS := -lSceUserService -lSceRegMgr -lSceSystemService -lkernel

signin-elf: bin/np-fake-signin-$(PLATFORM).elf

bin/np-fake-signin-$(PLATFORM).elf: np-fake-signin.c include/auth_dat.h include/config_dat.h
	$(CC) $(CFLAGS) -o $@ np-fake-signin.c $(LDFLAGS)

endif

# --- Shared: dat files and headers (platform-independent) ---

datfiles: template/config.dat template/account.dat template/token.dat template/auth.dat gen_dat/patch_dat_files.py
	python3 gen_dat/patch_dat_files.py patch template output $(NP_USER)

output/config.dat output/account.dat output/token.dat output/auth.dat: datfiles

headers: datfiles
	xxd -i output/auth.dat | sed 's/unsigned char .*\[\]/unsigned char auth_dat[]/; s/unsigned int .*/unsigned int auth_dat_len = sizeof(auth_dat);/' > include/auth_dat.h
	xxd -i output/account.dat | sed 's/unsigned char .*\[\]/unsigned char account_dat[]/; s/unsigned int .*/unsigned int account_dat_len = sizeof(account_dat);/' > include/account_dat.h
	xxd -i output/token.dat | sed 's/unsigned char .*\[\]/unsigned char token_dat[]/; s/unsigned int .*/unsigned int token_dat_len = sizeof(token_dat);/' > include/token_dat.h
	xxd -i output/config.dat | sed 's/unsigned char .*\[\]/unsigned char config_dat[]/; s/unsigned int .*/unsigned int config_dat_len = sizeof(config_dat);/' > include/config_dat.h


test-ps4: bin/np-fake-signin-ps4.elf
	nc $(PS4_HOST) $(PS4_PORT) < $<

test-ps5: bin/np-fake-signin-ps5.elf
	nc $(PS4_HOST) $(PS4_PORT) < $<

.PHONY: all build-ps4 build-ps5 clean datfiles headers signin-elf test-ps4 test-ps5
