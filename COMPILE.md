# Compile

## 安装 cmake

- https://cmake.org/download/ 下载对应版本

## Windows (Visual Studio)

    进入 scripts 目录
    双击  build-windows-msvs.bat
    生成的工程在 build-msvs/LNCORE.sln，直接使用 Visual Studio 打开即可

## Windows (Mingw64)

- 安装 mingw64
    - https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/7.1.0/threads-posix/seh/x86_64-7.1.0-release-posix-seh-rt_v5-rev2.7z

- 安装 Git Bash
    - https://npm.taobao.org/mirrors/git-for-windows/2.10.1.windows.1/Git-2.10.1-64-bit.exe    

- 在 Bash 里执行

```
./scripts/build-windows-mingw64.sh
```

- 输出动态库在 output/win 目录下

## Linux

```
./scripts/build-linux.sh
```

- 输出动态库在 output/linux 目录下

## Mac

```
./scripts/build-mac.sh
```

- 输出动态库在 output/mac 目录下

## Android

```
./scripts/build-android.sh
```

- 输出动态库在 output/android 目录下

## iOS

```
./scripts/build-ios.sh
```

- 输出动态库在 output/ios 目录下

