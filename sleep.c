// instruction numbered
#define SYS_WRITE 1
#define SYS_NANOSLEEP 35
#define SYS_EXIT 60

// timespec for func sleep
typedef struct timespec {
  long tv_sec;
  long tv_nsec;
} timespec;

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

int parse_int(char *raw_int) {
  int result = 0;
  char *cursor = raw_int;

  while (*cursor >= '0' && *cursor <= '9') {
    result = result * 10 + (*cursor - '0');
    cursor++;
  }

  return result;
}

long unsigned strlen(char *str) {
  char *cursor = str;

  while (*cursor) {
    cursor++;
  }

  long unsigned count = cursor - str;
  return count;
}

void print(char *str) { syscall_3(SYS_WRITE, 1, (long)str, strlen(str)); }

void sleep(long seconds) {
  timespec duration = {0};
  duration.tv_sec = seconds;

  syscall_2(SYS_NANOSLEEP, (long)(&duration), 0);
}

int main(int argc, char *argv[]) {
  if (argc != 2) {
    print("Usage: sleep NUMBER\nPause for NUMBER seconds\n");
    return 1;
  }

  char *raw_seconds = argv[1];
  long seconds = parse_int(raw_seconds);

  print("Sleeping for ");
  print(raw_seconds);
  print(" seconds\n");
  sleep(seconds);
}

void exit(long code) {
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
                       "call exit\n");
}
