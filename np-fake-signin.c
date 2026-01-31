/*
 * NP Fake Signin (by earthonion)
 * Requires offline activation via offact (https://github.com/ps5-payload-dev/offact)
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/user.h>

#include "include/auth_dat.h"
#ifndef PS5
#include "include/account_dat.h"
#include "include/token_dat.h"
#endif
#include "include/config_dat.h"
#include "hmac_md5.h"


#define ORBIS_USER_SERVICE_MAX_LOGIN_USERS 4

typedef struct { uint32_t priority; } OrbisUserServiceInitializeParams;
typedef struct {
    int32_t userId[ORBIS_USER_SERVICE_MAX_LOGIN_USERS];
} OrbisUserServiceLoginUserIdList;

int32_t sceUserServiceInitialize(OrbisUserServiceInitializeParams *params);
int32_t sceUserServiceTerminate(void);
int32_t sceUserServiceGetForegroundUser(int32_t *userId);
int32_t sceUserServiceGetLoginUserIdList(OrbisUserServiceLoginUserIdList *list);
int32_t sceUserServiceGetUserName(int32_t userId, char *name, size_t maxSize);

/* Notifications */
typedef struct notify_request {
    char useless1[45];
    char message[3075];
} notify_request_t;

int sceKernelSendNotificationRequest(int, notify_request_t*, size_t, int);

static void notify(const char *fmt, ...) {
    notify_request_t req;
    memset(&req, 0, sizeof(req));
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(req.message, sizeof(req.message), fmt, ap);
    va_end(ap);
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

#ifndef PS5
/* Debug functions for memory patching (PS4 only) */
int mdbg_copyout(int pid, unsigned long addr, void *buf, unsigned long len);
int mdbg_copyin(int pid, void *buf, unsigned long addr, unsigned long len);
#endif

/* Registry manager */
int32_t sceRegMgrSetInt(uint32_t key, int32_t value);
int32_t sceRegMgrSetStr(uint32_t key, const char *value, size_t size);
int32_t sceRegMgrSetBin(uint32_t key, const void *value, size_t size);
int32_t sceRegMgrGetStr(uint32_t key, char *value, size_t size);
int32_t sceRegMgrGetBin(uint32_t key, void *value, size_t size);

/* Registry keys from config.dat */
#define REG_KEY_USERNAME      125829632   /* offset 0x04, str 17 */
#define REG_KEY_ACCOUNT_ID    125830400   /* offset 0x100, bin 8 */
#define REG_KEY_EMAIL         125830656   /* offset 0x108, str 65 */
#define REG_KEY_NP_ENV        125874183   /* offset 0x177, str 17 */
#define REG_KEY_ONLINE_ID     125874188   /* offset 0x1AD, str 17 */
#define REG_KEY_COUNTRY       125874190   /* offset 0x1BE, str 3 */
#define REG_KEY_LANGUAGE      125874191   /* offset 0x1C1, str 6 */
#define REG_KEY_LOCALE        125874192   /* offset 0x1C7, str 36 */
#define REG_KEY_FLAG_1        125830144   /* offset 0x48, int */
#define REG_KEY_FLAG_2        125831168   /* offset 0x50, int */
#define REG_KEY_FLAG_3        125831424   /* offset 0x4C, int */
#define REG_KEY_FLAG_5C       125832960   /* offset 0x5C, int */
#define REG_KEY_FIELD_1F4     125874194   /* offset 0x1F4, int */
#define REG_KEY_SIGNIN_FLAG   125874185   /* offset 0x1F8, int - CRITICAL */
#define REG_KEY_FIELD_1FC     125874186   /* offset 0x1FC, int */
#define REG_KEY_NP_0xA4       125830912   /* offset 0xA4, int */
#define REG_KEY_NP_0xB4       125831936   /* offset 0xB4, int */
#define REG_KEY_NP_0xD0       125832704   /* offset 0xD0, int */
#define REG_KEY_NP_0xD4       125882625   /* offset 0xD4, int */
#define REG_KEY_NP_0xDC       125854723   /* offset 0xDC, int */
#define REG_KEY_NP_0xF4       125833216   /* offset 0xF4, int */
#define REG_KEY_EXT_0x1100    125874189   /* offset 0x1100, str 65 */
#define REG_KEY_EXT_0x1141    125874193   /* offset 0x1141, str 11 */
#define REG_KEY_EXT_0x114C    125874195   /* offset 0x114C, str 65 */

/* Signin state to patch */
#ifndef PATCH_STATE
#define PATCH_STATE 8
#endif

/* Runtime config.dat buffer - patched per-user */
static unsigned char cfg[sizeof(config_dat)];

#ifndef PS5
/* Runtime account.dat buffer - patched per-user */
static unsigned char acct_buf[sizeof(account_dat)];

/* replace zeroes with key ;) */
static const uint8_t hmac_key[16] = {
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
};
#endif

static void patch_str(unsigned char *buf, int offset, const char *str, int max_len) {
    memset(&buf[offset], 0, max_len);
    int len = strlen(str);
    if (len > max_len - 1) len = max_len - 1;
    memcpy(&buf[offset], str, len);
}

static void build_config(const char *username, const uint8_t *account_id) {
    /* Start from embedded template (has magic, version, flags, country, etc.) */
    memcpy(cfg, config_dat, sizeof(config_dat));

    /* Patch username at 0x04 */
    patch_str(cfg, 0x04, username, 17);

    /* Patch account_id at 0x100 */
    memcpy(&cfg[0x100], account_id, 8);

    /* Copy username as online_id at 0x1AD */
    patch_str(cfg, 0x1AD, username, 17);

    /* Build np_email: username@a8.COUNTRY.np.playstation.net */
    {
        char country[3] = {0};
        memcpy(country, &cfg[0x1BE], 2);
        if (country[0] == 0) { country[0] = 'u'; country[1] = 's'; }

        char np_email[65] = {0};
        snprintf(np_email, sizeof(np_email), "%s@a8.%s.np.playstation.net", username, country);

        /* Patch email at 0x108 (must match other fields for persistence) */
        patch_str(cfg, 0x108, np_email, 65);

        /* Patch np_email at 0x1100 */
        patch_str(cfg, 0x1100, np_email, 65);
    }

    printf("  Built config.dat for '%s' (id: %02x%02x%02x%02x%02x%02x%02x%02x)\n",
           username,
           account_id[0], account_id[1], account_id[2], account_id[3],
           account_id[4], account_id[5], account_id[6], account_id[7]);
}

#ifndef PS5
static void build_account(const char *online_id, const uint8_t *account_id) {
    /*
     * account.dat layout (224 bytes):
     *   0x00-0x07: magic + version
     *   0x08-0x0F: account_id (8 bytes)
     *   0x10-0x4F: hash_token (64 bytes)
     *   0x50:      status
     *   0x51-0x5F: online_id (15 bytes)
     *   0x65-0x6C: region (8 bytes)
     *   0x75-0x76: country (2 bytes)
     *   0x80-0x81: language (2 bytes)
     *   0x88-0x8F: locale (8 bytes)
     *   0xB8-0xBF: padding
     *   0xC0-0xDF: HMAC-MD5 as ASCII hex (32 bytes) over 0x00-0xB7
     */
    memcpy(acct_buf, account_dat, sizeof(account_dat));

    /* Patch account_id at 0x08 */
    memcpy(&acct_buf[0x08], account_id, 8);

    /* Patch online_id at 0x51 */
    patch_str(acct_buf, 0x51, online_id, 15);

    /* Recompute HMAC over 0x00-0xB7, store as ASCII hex at 0xC0 */
    char hex[33];
    hmac_md5_hex(hmac_key, sizeof(hmac_key), acct_buf, 0xB8, hex);
    memcpy(&acct_buf[0xC0], hex, 32);

    printf("  Built account.dat for '%s' (hmac: %.16s...)\n",
           online_id, &acct_buf[0xC0]);
}
#endif

static int write_file(const char *path, const unsigned char *data, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t written = write(fd, data, len);
    close(fd);
    return (written == (ssize_t)len) ? 0 : -1;
}

#ifndef PS5
static pid_t find_process(const char *name) {
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_PROC, 0};
    size_t buf_size;
    void *buf;
    pid_t result = -1;
    if (sysctl(mib, 4, NULL, &buf_size, NULL, 0)) return -1;
    buf = malloc(buf_size);
    if (!buf) return -1;
    if (sysctl(mib, 4, buf, &buf_size, NULL, 0)) { free(buf); return -1; }
    for (void *ptr = buf; ptr < (buf + buf_size);) {
        struct kinfo_proc *ki = (struct kinfo_proc *)ptr;
        ptr += ki->ki_structsize;
        if (strstr(ki->ki_comm, name) != NULL) { result = ki->ki_pid; break; }
    }
    free(buf);
    return result;
}
#endif

static int write_np_file(uint32_t userId, const char *fmt,
                         const unsigned char *data, size_t len, const char *label) {
    char path[256];
    snprintf(path, sizeof(path), fmt, userId);
    if (write_file(path, data, len) == 0) {
        printf("  Wrote %s\n", label);
        return 0;
    }
    printf("  Failed to write %s\n", label);
    return -1;
}

static void write_np_files(uint32_t userId) {
    char dir[256];
    snprintf(dir, sizeof(dir), "/system_data/priv/home/%x/np", userId);
    mkdir(dir, 0755);
#ifndef PS5
    snprintf(dir, sizeof(dir), "/user/home/%x/np", userId);
    mkdir(dir, 0755);
#endif

    write_np_file(userId, "/system_data/priv/home/%x/np/auth.dat",
                  auth_dat, sizeof(auth_dat), "auth.dat");
#ifndef PS5
    write_np_file(userId, "/user/home/%x/np/account.dat",
                  acct_buf, sizeof(acct_buf), "account.dat");
    write_np_file(userId, "/user/home/%x/np/token.dat",
                  token_dat, sizeof(token_dat), "token.dat");
#endif
    write_np_file(userId, "/system_data/priv/home/%x/config.dat",
                  cfg, sizeof(cfg), "config.dat");
}


static void set_registry_from_config(void) {
    int32_t val;

    sceRegMgrSetStr(REG_KEY_USERNAME, (const char*)&cfg[0x04], 17);
    sceRegMgrSetBin(REG_KEY_ACCOUNT_ID, &cfg[0x100], 8);
    if (cfg[0x108] != 0)
        sceRegMgrSetStr(REG_KEY_EMAIL, (const char*)&cfg[0x108], 65);
    sceRegMgrSetStr(REG_KEY_NP_ENV, (const char*)&cfg[0x177], 17);
    sceRegMgrSetStr(REG_KEY_ONLINE_ID, (const char*)&cfg[0x1AD], 17);
    sceRegMgrSetStr(REG_KEY_COUNTRY, (const char*)&cfg[0x1BE], 3);
    sceRegMgrSetStr(REG_KEY_LANGUAGE, (const char*)&cfg[0x1C1], 6);
    sceRegMgrSetStr(REG_KEY_LOCALE, (const char*)&cfg[0x1C7], 36);

    memcpy(&val, &cfg[0x48], 4); sceRegMgrSetInt(REG_KEY_FLAG_1, val);
    memcpy(&val, &cfg[0x4C], 4); sceRegMgrSetInt(REG_KEY_FLAG_3, val);
    memcpy(&val, &cfg[0x50], 4); sceRegMgrSetInt(REG_KEY_FLAG_2, val);
    memcpy(&val, &cfg[0x5C], 4); sceRegMgrSetInt(REG_KEY_FLAG_5C, val);
    memcpy(&val, &cfg[0x1F4], 4); sceRegMgrSetInt(REG_KEY_FIELD_1F4, val);
    memcpy(&val, &cfg[0x1F8], 4); sceRegMgrSetInt(REG_KEY_SIGNIN_FLAG, val);
    memcpy(&val, &cfg[0x1FC], 4); sceRegMgrSetInt(REG_KEY_FIELD_1FC, val);
    memcpy(&val, &cfg[0xA4], 4); sceRegMgrSetInt(REG_KEY_NP_0xA4, val);
    memcpy(&val, &cfg[0xB4], 4); sceRegMgrSetInt(REG_KEY_NP_0xB4, val);
    memcpy(&val, &cfg[0xD0], 4); sceRegMgrSetInt(REG_KEY_NP_0xD0, val);
    memcpy(&val, &cfg[0xD4], 4); sceRegMgrSetInt(REG_KEY_NP_0xD4, val);
    memcpy(&val, &cfg[0xDC], 4); sceRegMgrSetInt(REG_KEY_NP_0xDC, val);
    memcpy(&val, &cfg[0xF4], 4); sceRegMgrSetInt(REG_KEY_NP_0xF4, val);

    if (cfg[0x1100] != 0)
        sceRegMgrSetStr(REG_KEY_EXT_0x1100, (const char*)&cfg[0x1100], 65);
    if (cfg[0x1141] != 0)
        sceRegMgrSetStr(REG_KEY_EXT_0x1141, (const char*)&cfg[0x1141], 11);
    if (cfg[0x114C] != 0)
        sceRegMgrSetStr(REG_KEY_EXT_0x114C, (const char*)&cfg[0x114C], 65);

    printf("  Registry updated\n");
}

#ifndef PS5
/*
 * NpMgrUserCtx structure offsets:
 *   +0x0C = userId (4 bytes)
 *   +0x10 = state (4 bytes)
 *   +0x78 = account_id (8 bytes)
 *   +0xC4 = online_id (17 bytes)
 *   +0xD9 = online_id_valid (1 byte)
 *   +0xDA = flag (1 byte)
 *   +0xE8 = hash_token (64 bytes)
 *   +0x128 = null terminator
 *   +0x129 = online_id copy (16 bytes)
 *   +0x13E = region (8 bytes)
 *   +0x145 = region_valid flag
 *   +0x14D = country (2 bytes)
 *   +0x168 = language (2 bytes)
 *   +0x170 = locale (8 bytes)
 *   +0x1A5 = access_token (64 bytes)
 */
static void patch_signin_state(pid_t pid, uint32_t userId, int32_t new_state) {
    uint8_t buf[0x1000];
    const char *pattern = "/system_data/priv/home/";
    int pattern_len = 23;
    uint8_t one = 1;
    uint8_t zero = 0;

    printf("  Scanning ShellCore memory...\n");

    for (uint64_t addr = 0x880000000ULL; addr < 0x882000000ULL; addr += 0x1000) {
        if (mdbg_copyout(pid, addr, buf, 0x1000) != 0) continue;

        for (int i = 0; i <= 0x1000 - pattern_len; i++) {
            if (memcmp(&buf[i], pattern, pattern_len) == 0) {
                uint64_t ctx_addr = addr + i - 0x2C;
                uint32_t ctx_userid = 0;
                uint32_t ctx_state = 0;

                mdbg_copyout(pid, ctx_addr + 0x0C, &ctx_userid, 4);
                mdbg_copyout(pid, ctx_addr + 0x10, &ctx_state, 4);

                if (ctx_userid != userId || ctx_state > 8) continue;

                printf("  Found user context at 0x%lx (state=%d)\n", ctx_addr, ctx_state);

                /* Source fields from runtime config (cfg) */
                mdbg_copyin(pid, (void*)&cfg[0x100], ctx_addr + 0x78, 8);

                mdbg_copyin(pid, (void*)&cfg[0x1AD], ctx_addr + 0xC4, 17);

                /* hash_token from runtime account.dat */
                mdbg_copyin(pid, (void*)&acct_buf[0x10], ctx_addr + 0xE8, 64);

                mdbg_copyin(pid, &zero, ctx_addr + 0x128, 1);
                mdbg_copyin(pid, (void*)&cfg[0x1AD], ctx_addr + 0x129, 16);

                mdbg_copyin(pid, (void*)&cfg[0x177], ctx_addr + 0x13E, 8);
                mdbg_copyin(pid, (void*)&cfg[0x1BE], ctx_addr + 0x14D, 2);
                mdbg_copyin(pid, (void*)&cfg[0x1C1], ctx_addr + 0x168, 2);
                mdbg_copyin(pid, (void*)&cfg[0x1C7], ctx_addr + 0x170, 8);

                /* Set access_token from auth.dat offset 0x44 */
                mdbg_copyin(pid, (void*)&auth_dat[0x44], ctx_addr + 0x1A5, 64);

                /* Set valid flags */
                mdbg_copyin(pid, &one, ctx_addr + 0xD9, 1);  /* online_id_valid */
                mdbg_copyin(pid, &one, ctx_addr + 0xDA, 1);  /* flag */
                mdbg_copyin(pid, &one, ctx_addr + 0x145, 1); /* region_valid */

                /* Set signin state */
                mdbg_copyin(pid, &new_state, ctx_addr + 0x10, 4);

                printf("  Signin state set to %d\n", new_state);
                return;
            }
        }
    }
    printf("  Could not find user context for 0x%x\n", userId);
}
#endif

int main() {
    printf("NP Fake Signin (by earthonion)\n");
    printf("Offline activation by ps5-payload-dev\n\n");

    OrbisUserServiceInitializeParams params = { .priority = 0x2BC };
    sceUserServiceInitialize(&params);

    /* Get foreground user */
    int32_t fgUser = -1;
    sceUserServiceGetForegroundUser(&fgUser);
    if (fgUser < 0) {
        printf("No foreground user found\n");
        notify("No user found");
        sceUserServiceTerminate();
        return 1;
    }

    uint32_t userId = (uint32_t)fgUser;
    char userName[17] = {0};
    sceUserServiceGetUserName(userId, userName, sizeof(userName));
    printf("User: %s (0x%x)\n\n", userName, userId);

#ifndef PS5
    /* Find ShellCore (PS4 only - needed for memory patching) */
    pid_t pid = find_process("SceShellCore");
    if (pid < 0) {
        printf("ShellCore not found\n");
        notify("ShellCore not found");
        sceUserServiceTerminate();
        return 1;
    }
#endif

    /* Check activation (requires offact to have been run separately) */
    printf("Checking activation...\n");
    int account_numb = 0;
    uint64_t acct_id64 = 0;
    for (int n = 1; n <= 16; n++) {
        uint32_t off = (n - 1) * 65536;
        char name[32] = {0};
        sceRegMgrGetStr(REG_KEY_USERNAME + off, name, sizeof(name));
        if (name[0] && strcmp(name, userName) == 0) {
            account_numb = n;
            break;
        }
    }
    if (account_numb > 0) {
        uint32_t off = (account_numb - 1) * 65536;
        sceRegMgrGetBin(REG_KEY_ACCOUNT_ID + off, &acct_id64, sizeof(acct_id64));
    }
    if (!acct_id64) {
        printf("  Not activated!\n");
        notify("Not Activated! Aborting");
        sceUserServiceTerminate();
        return 1;
    }
    printf("  Activated (slot %d, id: 0x%lx)\n", account_numb, acct_id64);

    /* Build dat files */
    printf("\nGenerating dat files...\n");
    uint8_t acct_id[8];
    memcpy(acct_id, &acct_id64, 8);
    build_config(userName, acct_id);
#ifndef PS5
    build_account(userName, acct_id);
#endif

    /* Write dat files */
    printf("\nWriting files...\n");
    write_np_files(userId);

    /* Set registry */
    printf("\nSetting registry...\n");
    set_registry_from_config();

#ifndef PS5
    /* Patch signin state in memory (PS4 only) */
    printf("\nPatching signin state...\n");
    patch_signin_state(pid, userId, PATCH_STATE);
#endif

    printf("\nDone! Reboot to apply changes.\n");
    notify("\xf0\x9f\x91\x8d Signed in! Reboot to apply.");

    sceUserServiceTerminate();
    return 0;
}
