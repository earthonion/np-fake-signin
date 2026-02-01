# NP Fake Signin

ELF payload for PS4/PS5 that fakes PSN sign-in for the foreground user by writing NP files and patching registry/ShellCore state.

> [!NOTE] 
> **reverse sign in (sign out)**
> Settings > Users and Accounts > Other > Sign out

## Prerequisites

- Offline activation via [offact](https://github.com/ps5-payload-dev/offact) (account must have a non-zero account ID)
- [PS4 Payload SDK](https://github.com/ps4-payload-dev/sdk/) or [PS5 Payload SDK](https://github.com/ps5-payload-dev/sdk)
- HMAC-MD5 key for dat file signing (replace the zeroes in source files with the real key)

## Building

Set up the respective PS4 or PS5 SDK. Replace the zeroed HMAC key in `np-fake-signin.c` and `gen_dat/*.py` with the real key before building.

```sh
# PS4 only
make build-ps4

# PS5 only
make build-ps5

# Both (default)
make all

# Custom username for template dat files
make all NP_USER=MyUser
```

Output ELFs are placed in `bin/`.

## How it works

1. Checks the foreground user's activation status (aborts if account ID is 0)
2. Patches `config.dat` and `account.dat` templates with the user's account info
3. Writes NP files (`auth.dat`, `account.dat`, `token.dat`, `config.dat`) to the user's home directory
4. Sets registry keys for sign-in state (signin flag, birthday, account ID, etc.)
5. Patches ShellCore process memory to update the user context

Reboot after running to apply changes.
