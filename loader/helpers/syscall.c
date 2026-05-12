#include "syscall.h"

#ifndef __NR_clone
# define __NR_clone 220
#endif

ssize_t
frida_syscall_4 (size_t n, size_t a, size_t b, size_t c, size_t d)
{
  ssize_t result;

  register ssize_t x8 asm ("x8") = n;
  register  size_t x0 asm ("x0") = a;
  register  size_t x1 asm ("x1") = b;
  register  size_t x2 asm ("x2") = c;
  register  size_t x3 asm ("x3") = d;

  asm volatile (
      "svc 0x0\n\t"
      : "+r" (x0)
      : "r" (x1),
        "r" (x2),
        "r" (x3),
        "r" (x8)
      : "memory"
  );

  result = x0;

  return result;
}

ssize_t
frida_syscall_6 (size_t n, size_t a, size_t b, size_t c, size_t d, size_t e, size_t f)
{
  ssize_t result;

  register ssize_t x8 asm ("x8") = n;
  register  size_t x0 asm ("x0") = a;
  register  size_t x1 asm ("x1") = b;
  register  size_t x2 asm ("x2") = c;
  register  size_t x3 asm ("x3") = d;
  register  size_t x4 asm ("x4") = e;
  register  size_t x5 asm ("x5") = f;

  asm volatile (
      "svc 0x0\n\t"
      : "+r" (x0)
      : "r" (x1),
        "r" (x2),
        "r" (x3),
        "r" (x4),
        "r" (x5),
        "r" (x8)
      : "memory"
  );

  result = x0;

  return result;
}

ssize_t
frida_clone_thread (size_t flags, void * child_stack, void (* child_func) (void *), void * child_arg)
{
  register  size_t x8 asm ("x8") = __NR_clone;
  register  size_t x0 asm ("x0") = flags;
  register  size_t x1 asm ("x1") = (size_t) child_stack;
  register  size_t x2 asm ("x2") = 0;
  register  size_t x3 asm ("x3") = 0;
  register  size_t x4 asm ("x4") = 0;
  register  size_t x5 asm ("x5") = (size_t) child_func;
  register  size_t x6 asm ("x6") = (size_t) child_arg;

  asm volatile (
      "svc 0x0\n\t"
      "cbnz x0, 1f\n\t"
      "mov x0, x6\n\t"
      "blr x5\n\t"
      "mov x8, #93\n\t"
      "mov x0, #0\n\t"
      "svc 0x0\n\t"
      "1:\n\t"
      : "+r" (x0)
      : "r" (x1),
        "r" (x2),
        "r" (x3),
        "r" (x4),
        "r" (x5),
        "r" (x6),
        "r" (x8)
      : "memory", "cc", "x30"
  );

  return x0;
}

ssize_t
frida_syscall_5 (size_t n, size_t a, size_t b, size_t c, size_t d, size_t e)
{
  ssize_t result;

  register ssize_t x8 asm ("x8") = n;
  register  size_t x0 asm ("x0") = a;
  register  size_t x1 asm ("x1") = b;
  register  size_t x2 asm ("x2") = c;
  register  size_t x3 asm ("x3") = d;
  register  size_t x4 asm ("x4") = e;

  asm volatile (
      "svc 0x0\n\t"
      : "+r" (x0)
      : "r" (x1),
        "r" (x2),
        "r" (x3),
        "r" (x4),
        "r" (x8)
      : "memory"
  );

  result = x0;

  return result;
}
