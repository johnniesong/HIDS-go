#!/bin/bash
set -euxo pipefail

# 定义通用参数
SOURCE_DIR=.
LINUX_OUTPUT=bin/hidsgo

# 构建Linux版本
build_linux() {
    rm -f $LINUX_OUTPUT
    export GOOS=linux
    export GOARCH=amd64
    env CGO_ENABLED=0 go build -ldflags '-w -s' -o "$LINUX_OUTPUT" "$SOURCE_DIR"
    echo "Build completed for Linux x86_64."
}


# 主函数
main() {
    build_linux
}

# 运行主函数
main
