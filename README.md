# Mist

Hide custom Binder services registered in Android's ServiceManager, preventing third-party apps from discovering them.

## Why

Root modules often need IPC channels between system processes and apps. ServiceManager is a natural bridge for this -- just register a Binder service and you're good to go.

The catch? `ServiceManager::listServices` doesn't check SELinux permissions. **Any app can enumerate all registered services**, making your custom service an easy detection target.

Mist solves this by intercepting ServiceManager at runtime, filtering hidden services from unauthorized callers, and providing per-package access control.

## Features

- **Service hiding** -- Services registered with a special flag become invisible to unauthorized apps via `listServices`
- **Access control** -- Fine-grained per-package whitelist for discovering and connecting to hidden services
- **Dynamic whitelist** -- Manage allowed packages at runtime through a Binder interface or CLI

## Installation

Flash `module.zip` via Magisk / KernelSU and reboot. The module activates automatically during boot.

## Usage

### Whitelist management

Control which apps can discover and access hidden services:

```bash
# List whitelisted packages
mist whitelist list

# Check if a package is whitelisted
mist whitelist get <package_name>

# Add or remove a package
mist whitelist set <package_name> <1|0>
```

### Registering hidden services

Register your Binder service with the `DUMP_FLAG_PRIORITY_HIDE` flag (`1 << 24`) to make it hidden. Only whitelisted apps will be able to discover it through `listServices` or access `mist/`-prefixed services via `checkService` / `getService`.

## Building from source

### Prerequisites

- Android NDK (set `ANDROID_NDK` environment variable)
- Rust toolchain with `aarch64-linux-android` target
- [just](https://github.com/casey/just)

```bash
rustup target add aarch64-linux-android
```

### Build

```bash
just build                 # Build (release by default)
just package-module        # Package as Magisk module
```

Both commands accept an optional `debug` or `release` argument. The module zip is output to `target/module-<variant>.zip`.

## Acknowledgements

- [wisp](https://github.com/Mufanc/wisp) -- Inline hook / intercept framework
- [r3solvr](https://github.com/Mufanc/r3solvr) -- Runtime symbol resolver
