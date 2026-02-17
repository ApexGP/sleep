// ---------- platform selection ----------
#if defined(_WIN32)
#define PLATFORM_WINDOWS 1
#pragma comment(lib, "kernel32")
#else
#define PLATFORM_WINDOWS 0
#endif

// ---------- platform-specific constants / imports ----------
#if PLATFORM_WINDOWS
typedef unsigned long DWORD;
typedef unsigned int UINT;
typedef unsigned long long size_t;
typedef int BOOL;
typedef void *HANDLE;
typedef char *LPSTR;
typedef const char *LPCSTR;
typedef void *LPVOID;

#ifndef NULL
#define NULL ((void *)0)
#endif

#define STD_OUTPUT_HANDLE ((DWORD) - 11)
#define STD_ERROR_HANDLE ((DWORD) - 12)
#define INVALID_HANDLE_VALUE ((HANDLE)(long long)-1)

typedef struct OVERLAPPED {
  unsigned long Internal;
  unsigned long InternalHigh;
  union {
    struct {
      DWORD Offset;
      DWORD OffsetHigh;
    };
    void *Pointer;
  };
  HANDLE hEvent;
} OVERLAPPED;

__attribute__((dllimport)) HANDLE GetStdHandle(DWORD nStdHandle);
__attribute__((dllimport)) BOOL WriteFile(HANDLE hFile, const void *lpBuffer,
                                          DWORD nNumberOfBytesToWrite,
                                          DWORD *lpNumberOfBytesWritten,
                                          OVERLAPPED *lpOverlapped);
__attribute__((dllimport)) LPVOID GetProcessHeap(void);
__attribute__((dllimport)) LPVOID HeapAlloc(HANDLE hHeap, DWORD dwFlags,
                                            size_t dwBytes);
__attribute__((dllimport)) BOOL HeapFree(HANDLE hHeap, DWORD dwFlags,
                                         LPVOID lpMem);
__attribute__((dllimport)) LPSTR GetCommandLineA(void);
__attribute__((dllimport, noreturn)) void ExitProcess(UINT uExitCode);
__attribute__((dllimport)) void Sleep(DWORD dwMilliseconds);
#elif defined(__linux__)
#define SYS_WRITE 1
#define SYS_NANOSLEEP 35
#define SYS_EXIT 60
#elif defined(__APPLE__)
#define SYS_WRITE 0x2000004
#define SYS_SELECT 0x200005D
#define SYS_EXIT 0x2000001
#else
#error Unsupported platform
#endif

#define EINTR_CODE 4

#if PLATFORM_WINDOWS
#define LONG_MAX_VALUE 2147483647L
#define WINDOWS_MAX_SLEEP_SECONDS 2147483L
#else
#define LONG_MAX_VALUE 9223372036854775807L
#endif

// ---------- shared types ----------
typedef struct timespec {
  long tv_sec;
  long tv_nsec;
} timespec;

typedef struct timeval {
  long tv_sec;
  long tv_usec;
} timeval;

#if PLATFORM_WINDOWS
__attribute__((weak)) void __main(void) {}
#endif

// ---------- non-Windows syscall shims ----------
#if !PLATFORM_WINDOWS
#if defined(__x86_64__)
long syscall_1(long code, long arg1) {
  long result;
  __asm__ __volatile__("syscall"
                       : "=a"(result)
                       : "a"(code), "D"(arg1)
                       : "rcx", "r11", "memory");
  return result;
}

long syscall_2(long code, long arg1, long arg2) {
  long result;
  __asm__ __volatile__("syscall"
                       : "=a"(result)
                       : "a"(code), "D"(arg1), "S"(arg2)
                       : "rcx", "r11", "memory");
  return result;
}

long syscall_3(long code, long arg1, long arg2, long arg3) {
  long result;
  __asm__ __volatile__("syscall"
                       : "=a"(result)
                       : "a"(code), "D"(arg1), "S"(arg2), "d"(arg3)
                       : "rcx", "r11", "memory");
  return result;
}

long syscall_5(long code, long arg1, long arg2, long arg3, long arg4,
               long arg5) {
  long result;
  __asm__ __volatile__("mov %4, %%r10\n\t"
                       "mov %5, %%r8\n\t"
                       "syscall"
                       : "=a"(result)
                       : "a"(code), "D"(arg1), "S"(arg2), "d"(arg3), "r"(arg4),
                         "r"(arg5)
                       : "rcx", "r11", "r8", "r10", "memory");
  return result;
}
#elif defined(__aarch64__) || defined(__arm64__)
long syscall_1(long code, long arg1) {
  long result;
  __asm__ __volatile__("mov x16, %1\n\t"
                       "mov x0, %2\n\t"
                       "svc #0\n\t"
                       "mov %0, x0"
                       : "=r"(result)
                       : "r"(code), "r"(arg1)
                       : "x0", "x16", "memory");
  return result;
}

long syscall_2(long code, long arg1, long arg2) {
  long result;
  __asm__ __volatile__("mov x16, %1\n\t"
                       "mov x0, %2\n\t"
                       "mov x1, %3\n\t"
                       "svc #0\n\t"
                       "mov %0, x0"
                       : "=r"(result)
                       : "r"(code), "r"(arg1), "r"(arg2)
                       : "x0", "x1", "x16", "memory");
  return result;
}

long syscall_3(long code, long arg1, long arg2, long arg3) {
  long result;
  __asm__ __volatile__("mov x16, %1\n\t"
                       "mov x0, %2\n\t"
                       "mov x1, %3\n\t"
                       "mov x2, %4\n\t"
                       "svc #0\n\t"
                       "mov %0, x0"
                       : "=r"(result)
                       : "r"(code), "r"(arg1), "r"(arg2), "r"(arg3)
                       : "x0", "x1", "x2", "x16", "memory");
  return result;
}

long syscall_5(long code, long arg1, long arg2, long arg3, long arg4,
               long arg5) {
  long result;
  __asm__ __volatile__("mov x16, %1\n\t"
                       "mov x0, %2\n\t"
                       "mov x1, %3\n\t"
                       "mov x2, %4\n\t"
                       "mov x3, %5\n\t"
                       "mov x4, %6\n\t"
                       "svc #0\n\t"
                       "mov %0, x0"
                       : "=r"(result)
                       : "r"(code), "r"(arg1), "r"(arg2), "r"(arg3), "r"(arg4),
                         "r"(arg5)
                       : "x0", "x1", "x2", "x3", "x4", "x16", "memory");
  return result;
}
#else
#error Unsupported architecture for syscall shims
#endif
#endif

// ---------- small utilities ----------
static long unsigned my_strlen(const char *str) {
  const char *cursor = str;
  while (*cursor) {
    cursor++;
  }
  return (long unsigned)(cursor - str);
}

static long unsigned my_strlen_nullok(const char *str) {
  if (!str) {
    return 0;
  }
  return my_strlen(str);
}

// ---------- I/O ----------
long write_all(long fd, const char *str, long unsigned len) {
#if PLATFORM_WINDOWS
  HANDLE handle = INVALID_HANDLE_VALUE;
  if (fd == 1) {
    handle = GetStdHandle(STD_OUTPUT_HANDLE);
  } else if (fd == 2) {
    handle = GetStdHandle(STD_ERROR_HANDLE);
  }
  if (handle == INVALID_HANDLE_VALUE) {
    return -1;
  }

  unsigned long long sent = 0;
  while (sent < len) {
    DWORD chunk =
        (DWORD)((len - sent) > 0xFFFFFFFFu ? 0xFFFFFFFFu : (len - sent));
    DWORD wrote = 0;
    if (!WriteFile(handle, str + sent, chunk, &wrote, NULL) || wrote == 0) {
      return -1;
    }
    sent += wrote;
  }

  return 0;
#else
  long unsigned sent = 0;
  while (sent < len) {
    long wrote = syscall_3(SYS_WRITE, fd, (long)(str + sent), len - sent);
    if (wrote < 0) {
      return wrote;
    }
    sent += wrote;
  }
  return 0;
#endif
}

void print(const char *str) { write_all(1, str, my_strlen(str)); }
void print_err(const char *str) { write_all(2, str, my_strlen(str)); }

// ---------- parsing ----------
int parse_seconds(char *raw, long *out_seconds) {
  if (!raw || !*raw) {
    return -1;
  }

  char *cursor = raw;
  if (*cursor == '+') {
    cursor++;
  }
  if (*cursor < '0' || *cursor > '9') {
    return -1;
  }

  long value = 0;
  while (*cursor) {
    char c = *cursor;
    if (c < '0' || c > '9') {
      return -1;
    }
    long digit = c - '0';
    if (value > (LONG_MAX_VALUE - digit) / 10) {
      return -2;
    }
    value = value * 10 + digit;
    cursor++;
  }

  *out_seconds = value;
  return 0;
}

// ---------- sleep ----------
long sleep_seconds(long seconds) {
#if PLATFORM_WINDOWS
  if (seconds < 0) {
    return -1;
  }
  if (seconds > WINDOWS_MAX_SLEEP_SECONDS) {
    return -2;
  }
  while (seconds > 0) {
    DWORD chunk_ms = (DWORD)(seconds * 1000u);
    Sleep(chunk_ms);
    seconds = 0;
  }
  return 0;
#elif defined(__linux__)
  timespec request = {0};
  timespec remaining = {0};
  request.tv_sec = seconds;

  while (1) {
    long result =
        syscall_2(SYS_NANOSLEEP, (long)(&request), (long)(&remaining));
    if (result == 0) {
      return 0;
    }
    if (result == -EINTR_CODE) {
      request = remaining;
      continue;
    }
    return result;
  }
#else
  /* macOS: no direct nanosleep syscall, use select(0,NULL,NULL,NULL,&tv) */
  timeval tv = {0};
  tv.tv_sec = seconds;
  tv.tv_usec = 0;
  long result = syscall_5(SYS_SELECT, 0, 0, 0, 0, (long)(&tv));
  return (result < 0) ? result : 0;
#endif
}

// ---------- core main ----------
int real_main(int argc, char *argv[]) {
  if (argc != 2) {
    print_err("Usage: sleep NUMBER\nPause for NUMBER seconds\n");
    return 1;
  }

  long seconds = 0;
  int parse_result = parse_seconds(argv[1], &seconds);
  if (parse_result != 0) {
    if (parse_result == -2) {
      print_err("Error: NUMBER is too large\n");
    } else {
      print_err("Error: invalid NUMBER (digits only, non-negative)\n");
    }
    return 1;
  }

  print("Sleeping for ");
  print(argv[1]);
  print(" seconds\n");

  long sleep_result = sleep_seconds(seconds);
  if (sleep_result != 0) {
    print_err("Sleep failed\n");
    return 1;
  }

  return 0;
}

#if !PLATFORM_WINDOWS
int main(int argc, char *argv[]) { return real_main(argc, argv); }
#endif

// ---------- Windows entry / argv ----------
#if PLATFORM_WINDOWS
typedef struct {
  char *storage;
  char *argv_items[2];
  int argc;
} win_args;

static win_args parse_windows_args(void) {
  win_args result;
  result.storage = NULL;
  result.argv_items[0] = NULL;
  result.argv_items[1] = NULL;
  result.argc = 0;

  char *cmd = GetCommandLineA();
  if (!cmd) {
    return result;
  }

  long unsigned len = my_strlen_nullok(cmd);
  HANDLE heap = GetProcessHeap();
  char *buffer = (char *)HeapAlloc(heap, 0, len + 1);
  if (!buffer) {
    return result;
  }

  for (long unsigned i = 0; i <= len; i++) {
    buffer[i] = cmd[i];
  }

  char *cursor = buffer;
  while (*cursor == ' ' || *cursor == '\t') {
    cursor++;
  }

  if (*cursor == '"') {
    cursor++;
    while (*cursor && *cursor != '"') {
      cursor++;
    }
    if (*cursor == '"') {
      cursor++;
    }
  } else {
    while (*cursor && *cursor != ' ' && *cursor != '\t') {
      cursor++;
    }
  }

  while (*cursor == ' ' || *cursor == '\t') {
    cursor++;
  }

  if (*cursor) {
    result.argv_items[1] = cursor;
    while (*cursor && *cursor != ' ' && *cursor != '\t' && *cursor != '"') {
      cursor++;
    }
    *cursor = '\0';
    result.argc = 2;
  } else {
    result.argc = 1;
  }

  result.storage = buffer;
  return result;
}

__attribute__((noreturn)) void mainCRTStartup(void) {
  win_args args = parse_windows_args();
  int code = real_main(args.argc, args.argv_items);
  if (args.storage) {
    HeapFree(GetProcessHeap(), 0, args.storage);
  }
  ExitProcess((UINT)code);
}

// ---------- non-Windows entry ----------
#else
__attribute__((noreturn)) void sys_exit(long code) {
  syscall_1(SYS_EXIT, code);
  for (;;) {
  }
}

#if defined(__x86_64__)
__attribute__((naked)) void _start(void) {
  __asm__ __volatile__("xor %ebp, %ebp\n"
                       "mov (%rsp), %rdi\n"
                       "lea 8(%rsp), %rsi\n"
                       "and $-16, %rsp\n"
                       "call main\n"
                       "mov %rax, %rdi\n"
                       "call sys_exit\n");
}
#elif defined(__aarch64__) || defined(__arm64__)
__attribute__((naked)) void _start(void) {
  /* dyld passes argc in x0, argv in x1 when calling program entry */
  __asm__ __volatile__("bl _main\n"
                       "bl _sys_exit\n"
                       "b .\n");
}
#else
#error Unsupported architecture for _start
#endif
#endif
