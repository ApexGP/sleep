## sleep (single-file, cross-platform)

This repository contains a single C source file that implements a minimal `sleep` utility without relying on the C standard library. Platform-specific sections handle Linux, macOS, and Windows with direct syscalls or minimal WinAPI imports.

### Build

- Linux/macOS (GCC/Clang):

  ```sh
  cc sleep.c -nostdlib -fno-stack-protector -o sleep
  ```

- Windows (MinGW):

  ```sh
  gcc sleep.c -nostdlib -fno-stack-protector -o sleep.exe -lkernel32
  ```

- Windows (MSVC):
  ```bat
  cl /GS- /c sleep.c
  link /NODEFAULTLIB /ENTRY:mainCRTStartup sleep.obj kernel32.lib
  ```
