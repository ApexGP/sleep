// instruction numbered
#if defined(_WIN32)
#define PLATFORM_WINDOWS 1
#include <windows.h>
#include <io.h>
#else
#define PLATFORM_WINDOWS 0
#endif

#if PLATFORM_WINDOWS
#elif defined(__linux__)
#define SYS_WRITE 1
#define SYS_NANOSLEEP 35
#define SYS_EXIT 60
#elif defined(__APPLE__)
#define SYS_WRITE 0x2000004
#define SYS_NANOSLEEP 0x20000F0
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

// timespec for func sleep
typedef struct timespec {
  long tv_sec;
  long tv_nsec;
} timespec;

#if !PLATFORM_WINDOWS
// custom syscall implementation
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
#endif

long unsigned strlen(const char *str) {
  const char *cursor = str;

  while (*cursor) {
    cursor++;
  }

  long unsigned count = cursor - str;
  return count;
}

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
    DWORD chunk = (DWORD)((len - sent) > 0xFFFFFFFFu ? 0xFFFFFFFFu : (len - sent));
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

void print(const char *str) { write_all(1, str, strlen(str)); }

void print_err(const char *str) { write_all(2, str, strlen(str)); }

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
#else
  timespec request = {0};
  timespec remaining = {0};
  request.tv_sec = seconds;

  while (1) {
    long result = syscall_2(SYS_NANOSLEEP, (long)(&request), (long)(&remaining));
    if (result == 0) {
      return 0;
    }
    if (result == -EINTR_CODE) {
      request = remaining;
      continue;
    }
    return result;
  }
#endif
}

int main(int argc, char *argv[]) {
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
__attribute__((noreturn)) void sys_exit(long code) {
  syscall_1(SYS_EXIT, code);
  for (;;) {
  }
}

// inline assembly code for _start()
__attribute__((naked)) void _start() {
  __asm__ __volatile__("xor %ebp, %ebp\n"
                        "mov (%rsp), %rdi\n"
                        "lea 8(%rsp), %rsi\n"
                        "and $-16, %rsp\n"
                        "call main\n"
                        "mov %rax, %rdi\n"
                        "call sys_exit\n");
}
#endif
