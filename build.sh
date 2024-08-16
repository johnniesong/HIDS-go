#!/bin/bash
set -euxo pipefail

# 定义通用参数
SOURCE_DIR=.
LINUX_OUTPUT=bin/hids-go
MAC_OUTPUT=bin/hids-go-mac-arm64

# 构建Linux版本
build_linux() {
    rm -f $LINUX_OUTPUT
    export GOOS=linux
    export GOARCH=amd64
    env CGO_ENABLED=0 go build -ldflags '-w -s' -o "$LINUX_OUTPUT" "$SOURCE_DIR"
    echo "Build completed for Linux x86_64."
}

# 构建Mac M1版本
build_mac_m1() {
    rm -f $MAC_OUTPUT
    export GOOS=darwin
    export GOARCH=arm64
    env CGO_ENABLED=0 go build -ldflags '-w -s' -o "$MAC_OUTPUT" "$SOURCE_DIR"
    echo "Build completed for Darwin arm64."
}

# 主函数，依次构建两个平台的二进制文件
main() {
    build_linux
    build_mac_m1

}

# 运行主函数
main
