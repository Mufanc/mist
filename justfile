#!/usr/bin/env just --justfile

TARGET_SDK := "35"

# https://developer.android.com/ndk/guides/other_build_systems#overview
HOST_TAG := (if os() == "macos" { "darwin" } else { os() }) + "-x86_64"

CC := env("ANDROID_NDK") / "toolchains/llvm/prebuilt" / HOST_TAG / "bin" / ("aarch64-linux-android" + TARGET_SDK + "-clang")

package-module variant="release": (build variant)
    rm -rf target/module-*.zip || true
    cp -R module target/module
    cp target/aarch64-linux-android/{{variant}}/mist target/module/bin
    cp target/aarch64-linux-android/{{variant}}/libmist.so target/module/bin
    rm target/module/bin/.keep
    cd target/module && zip -r ../module-{{variant}}.zip .
    rm -rf target/module

build variant="release":
    cargo build \
        --target aarch64-linux-android \
        {{ if variant == "release" { "--release" } else { "" } }} \
        --config target.aarch64-linux-android.linker=\"{{CC}}\"

test variant="release": (build variant)
    cargo test \
        --package mist_test \
        --test mist_test \
        --target aarch64-linux-android \
        {{ if variant == "release" { "--release" } else { "" } }} \
        --config target.aarch64-linux-android.linker=\"{{CC}}\"

clean:
    cargo clean
