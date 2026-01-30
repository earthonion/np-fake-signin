/* NP Fake Signin: Write NP files + Patch signin state + Set registry */
/* config.dat is generated at runtime using existing username + account_id */

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

/* Debug functions for memory patching */
int mdbg_copyout(int pid, unsigned long addr, void *buf, unsigned long len);
int mdbg_copyin(int pid, void *buf, unsigned long addr, unsigned long len);

/* Registry manager */
int32_t sceRegMgrSetInt(uint32_t key, int32_t value);
int32_t sceRegMgrSetStr(uint32_t key, const char *value, size_t size);
int32_t sceRegMgrSetBin(uint32_t key, const void *value, size_t size);
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
        patch_str(cfg, 0x1100, np_email, 65);
    }

    printf("    config.dat generated:\n");
    printf("      username:   %s\n", username);
    printf("      online_id:  %s\n", &cfg[0x1AD]);
    printf("      account_id: %02x%02x%02x%02x%02x%02x%02x%02x\n",
           account_id[0], account_id[1], account_id[2], account_id[3],
           account_id[4], account_id[5], account_id[6], account_id[7]);
    printf("      np_email:   %s\n", &cfg[0x1100]);
}

static int write_file(const char *path, const unsigned char *data, size_t len) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    ssize_t written = write(fd, data, len);
    close(fd);
    return (written == (ssize_t)len) ? 0 : -1;
}

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

static void write_np_files(uint32_t userId) {
    char path[256];

    /* Write auth.dat */
    snprintf(path, sizeof(path), "/system_data/priv/home/%x/np/auth.dat", userId);
    if (write_file(path, auth_dat, sizeof(auth_dat)) == 0) {
        printf("    Wrote %s\n", path);
    } else {
        printf("    FAILED: %s\n", path);
    }

#ifndef PS5
    /* Write account.dat (PS4 only) */
    snprintf(path, sizeof(path), "/user/home/%x/np/account.dat", userId);
    if (write_file(path, account_dat, sizeof(account_dat)) == 0) {
        printf("    Wrote %s\n", path);
    } else {
        printf("    FAILED: %s\n", path);
    }

    /* Write token.dat (PS4 only) */
    snprintf(path, sizeof(path), "/user/home/%x/np/token.dat", userId);
    if (write_file(path, token_dat, sizeof(token_dat)) == 0) {
        printf("    Wrote %s\n", path);
    } else {
        printf("    FAILED: %s\n", path);
    }
#endif

    /* Write config.dat (generated at runtime) */
    snprintf(path, sizeof(path), "/system_data/priv/home/%x/config.dat", userId);
    if (write_file(path, cfg, sizeof(cfg)) == 0) {
        printf("    Wrote %s\n", path);
    } else {
        printf("    FAILED: %s\n", path);
    }
}


static void set_registry_from_config(void) {
    int ret;
    int32_t val;

    printf("    Setting registry from config.dat...\n");

    /* Username */
    ret = sceRegMgrSetStr(REG_KEY_USERNAME, (const char*)&cfg[0x04], 17);
    printf("      username: '%s' (ret=%d)\n", (char*)&cfg[0x04], ret);

    /* Account ID - skip for now, preserve existing */
    /* ret = sceRegMgrSetBin(REG_KEY_ACCOUNT_ID, &cfg[0x100], 8); */
    /* printf("      account_id (ret=%d)\n", ret); */

    /* Email */
    if (cfg[0x108] != 0) {
        ret = sceRegMgrSetStr(REG_KEY_EMAIL, (const char*)&cfg[0x108], 65);
        printf("      email: '%s' (ret=%d)\n", (char*)&cfg[0x108], ret);
    }

    /* NP env */
    ret = sceRegMgrSetStr(REG_KEY_NP_ENV, (const char*)&cfg[0x177], 17);
    printf("      np_env: '%s' (ret=%d)\n", (char*)&cfg[0x177], ret);

    /* Online ID */
    ret = sceRegMgrSetStr(REG_KEY_ONLINE_ID, (const char*)&cfg[0x1AD], 17);
    printf("      online_id: '%s' (ret=%d)\n", (char*)&cfg[0x1AD], ret);

    /* Country/Language/Locale */
    ret = sceRegMgrSetStr(REG_KEY_COUNTRY, (const char*)&cfg[0x1BE], 3);
    printf("      country: '%.2s' (ret=%d)\n", (char*)&cfg[0x1BE], ret);
    ret = sceRegMgrSetStr(REG_KEY_LANGUAGE, (const char*)&cfg[0x1C1], 6);
    printf("      language: '%.2s' (ret=%d)\n", (char*)&cfg[0x1C1], ret);
    ret = sceRegMgrSetStr(REG_KEY_LOCALE, (const char*)&cfg[0x1C7], 36);
    printf("      locale: '%s' (ret=%d)\n", (char*)&cfg[0x1C7], ret);

    /* Integer flags at 0x48, 0x4C, 0x50, 0x5C */
    memcpy(&val, &cfg[0x48], 4);
    sceRegMgrSetInt(REG_KEY_FLAG_1, val);
    memcpy(&val, &cfg[0x4C], 4);
    sceRegMgrSetInt(REG_KEY_FLAG_3, val);
    memcpy(&val, &cfg[0x50], 4);
    sceRegMgrSetInt(REG_KEY_FLAG_2, val);
    memcpy(&val, &cfg[0x5C], 4);
    sceRegMgrSetInt(REG_KEY_FLAG_5C, val);

    /* Field 0x1F4 */
    memcpy(&val, &cfg[0x1F4], 4);
    ret = sceRegMgrSetInt(REG_KEY_FIELD_1F4, val);
    printf("      field_0x1F4: %d (ret=%d)\n", val, ret);

    /* CRITICAL: Signin flag at 0x1F8 */
    memcpy(&val, &cfg[0x1F8], 4);
    ret = sceRegMgrSetInt(REG_KEY_SIGNIN_FLAG, val);
    printf("      signin_flag: %d (ret=%d)\n", val, ret);

    /* Field 0x1FC */
    memcpy(&val, &cfg[0x1FC], 4);
    sceRegMgrSetInt(REG_KEY_FIELD_1FC, val);

    /* NP Manager fields */
    memcpy(&val, &cfg[0xA4], 4);
    sceRegMgrSetInt(REG_KEY_NP_0xA4, val);
    memcpy(&val, &cfg[0xB4], 4);
    sceRegMgrSetInt(REG_KEY_NP_0xB4, val);
    memcpy(&val, &cfg[0xD0], 4);
    sceRegMgrSetInt(REG_KEY_NP_0xD0, val);
    memcpy(&val, &cfg[0xD4], 4);
    sceRegMgrSetInt(REG_KEY_NP_0xD4, val);
    memcpy(&val, &cfg[0xDC], 4);
    sceRegMgrSetInt(REG_KEY_NP_0xDC, val);
    memcpy(&val, &cfg[0xF4], 4);
    sceRegMgrSetInt(REG_KEY_NP_0xF4, val);

    /* Extended fields */
    if (cfg[0x1100] != 0) {
        ret = sceRegMgrSetStr(REG_KEY_EXT_0x1100, (const char*)&cfg[0x1100], 65);
        printf("      np_email: '%s' (ret=%d)\n", (char*)&cfg[0x1100], ret);
    }
    if (cfg[0x1141] != 0) {
        ret = sceRegMgrSetStr(REG_KEY_EXT_0x1141, (const char*)&cfg[0x1141], 11);
        printf("      birthday: '%s' (ret=%d)\n", (char*)&cfg[0x1141], ret);
    }
    if (cfg[0x114C] != 0) {
        ret = sceRegMgrSetStr(REG_KEY_EXT_0x114C, (const char*)&cfg[0x114C], 65);
    }

    (void)ret;
}

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

    printf("    Scanning for NpMgrUserCtx...\n");

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

                printf("    Found ctx at 0x%lx (state=%d)\n", ctx_addr, ctx_state);

#ifdef PS5
                /* PS5: source fields from runtime config */
                mdbg_copyin(pid, (void*)&cfg[0x100], ctx_addr + 0x78, 8);

                mdbg_copyin(pid, (void*)&cfg[0x1AD], ctx_addr + 0xC4, 17);
                printf("    Set online_id: '%s'\n", (char*)&cfg[0x1AD]);

                /* hash_token - zeros on PS5 (no account.dat) */
                {
                    char zero_token[64] = {0};
                    mdbg_copyin(pid, zero_token, ctx_addr + 0xE8, 64);
                }

                mdbg_copyin(pid, &zero, ctx_addr + 0x128, 1);
                mdbg_copyin(pid, (void*)&cfg[0x1AD], ctx_addr + 0x129, 16);

                mdbg_copyin(pid, (void*)&cfg[0x177], ctx_addr + 0x13E, 8);
                mdbg_copyin(pid, (void*)&cfg[0x1BE], ctx_addr + 0x14D, 2);
                mdbg_copyin(pid, (void*)&cfg[0x1C1], ctx_addr + 0x168, 2);
                mdbg_copyin(pid, (void*)&cfg[0x1C7], ctx_addr + 0x170, 8);
#else
                /* PS4: source fields from account.dat */
                mdbg_copyin(pid, (void*)&account_dat[0x08], ctx_addr + 0x78, 8);

                mdbg_copyin(pid, (void*)&account_dat[0x51], ctx_addr + 0xC4, 17);
                printf("    Set online_id: '%s'\n", (char*)&account_dat[0x51]);

                mdbg_copyin(pid, (void*)&account_dat[0x10], ctx_addr + 0xE8, 64);

                mdbg_copyin(pid, &zero, ctx_addr + 0x128, 1);
                mdbg_copyin(pid, (void*)&account_dat[0x51], ctx_addr + 0x129, 16);

                mdbg_copyin(pid, (void*)&account_dat[0x65], ctx_addr + 0x13E, 8);
                mdbg_copyin(pid, (void*)&account_dat[0x75], ctx_addr + 0x14D, 2);
                mdbg_copyin(pid, (void*)&account_dat[0x80], ctx_addr + 0x168, 2);
                mdbg_copyin(pid, (void*)&account_dat[0x88], ctx_addr + 0x170, 8);
#endif

                /* Set access_token from auth.dat offset 0x44 */
                mdbg_copyin(pid, (void*)&auth_dat[0x44], ctx_addr + 0x1A5, 64);

                /* Set valid flags */
                mdbg_copyin(pid, &one, ctx_addr + 0xD9, 1);  /* online_id_valid */
                mdbg_copyin(pid, &one, ctx_addr + 0xDA, 1);  /* flag */
                mdbg_copyin(pid, &one, ctx_addr + 0x145, 1); /* region_valid */

                /* Set signin state */
                mdbg_copyin(pid, &new_state, ctx_addr + 0x10, 4);

                /* Verify */
                mdbg_copyout(pid, ctx_addr + 0x10, &ctx_state, 4);
                printf("    Patched state: %d -> %d\n", ctx_state, new_state);
                return;
            }
        }
    }
    printf("    WARNING: ctx not found for user 0x%x\n", userId);
}

int main() {
    printf("=== NP Fake Signin (by earthonion) ===\n\n");
    notify("NP Fake Signin: Starting...");

    OrbisUserServiceInitializeParams params = { .priority = 0x2BC };
    sceUserServiceInitialize(&params);

    /* Get users */
    OrbisUserServiceLoginUserIdList userList;
    memset(&userList, 0xFF, sizeof(userList));
    sceUserServiceGetLoginUserIdList(&userList);

    int userCount = 0;
    printf("[1] Logged in users:\n");
    for (int i = 0; i < ORBIS_USER_SERVICE_MAX_LOGIN_USERS; i++) {
        if (userList.userId[i] >= 0) {
            char name[17] = {0};
            sceUserServiceGetUserName(userList.userId[i], name, sizeof(name));
            printf("    0x%x (%s)\n", userList.userId[i], name);
            userCount++;
        }
    }

    if (userCount == 0) {
        printf("\nERROR: No users found!\n");
        sceUserServiceTerminate();
        return 1;
    }

    /* Find ShellCore */
    pid_t pid = find_process("SceShellCore");
    printf("\n[2] ShellCore PID: %d\n", pid);
    if (pid < 0) {
        printf("ERROR: ShellCore not found!\n");
        sceUserServiceTerminate();
        return 1;
    }

    /* Process each user */
    for (int i = 0; i < ORBIS_USER_SERVICE_MAX_LOGIN_USERS; i++) {
        if (userList.userId[i] < 0) continue;

        uint32_t userId = userList.userId[i];
        char userName[17] = {0};
        sceUserServiceGetUserName(userId, userName, sizeof(userName));

        printf("\n[3] Processing user 0x%x (%s)\n", userId, userName);

        /* Step 0: Read existing account_id from registry, build config.dat */
        printf("  Step 0: Generating config.dat...\n");
        uint8_t acct_id[8] = {0};
        sceRegMgrGetBin(REG_KEY_ACCOUNT_ID, acct_id, 8);
        build_config(userName, acct_id);

        /* Step 1: Write dat files */
        printf("  Step 1: Writing dat files...\n");
        write_np_files(userId);

        /* Step 2: Set registry */
        printf("  Step 2: Setting registry...\n");
        set_registry_from_config();

        /* Step 3: Patch state */
        printf("  Step 3: Patching signin state to %d...\n", PATCH_STATE);
        patch_signin_state(pid, userId, PATCH_STATE);
    }

    printf("\n=== Done! ===\n");
    printf("Registry updated. State patched to %d.\n", PATCH_STATE);
    printf("Reboot to apply persistent changes.\n");

    sleep(2);
    notify("Reboot to apply changes!!");

    sceUserServiceTerminate();
    return 0;
}
