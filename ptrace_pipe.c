// TODO: do page fault stuff so that we can detect how much memory the system is actually using?
// TODO: if we ever need to read something from userland, we need to make sure we don't fault.
//       can preemptively do this by checking /proc/child_pid/maps? But then another process can evidently change that
//       from underneath us, maybe?
// TODO: we might need to eventually write to the filesystem of the internal buffer of things gets too big?
// TODO: how long do instructions actually take? if we can determine that, we can use this to make the big board
// deterministic. Can even then account for memory accesses if we measure cache timings
//

// for kill
#define _POSIX_SOURCE

#include <sys/ptrace.h>
#include <linux/ptrace.h> // for PTRACE_SYSEMU, rather than sys/ptrace.h
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include <signal.h>

#include "syscall_map.h"

// TODO: are there are other system call opcodes?
// http://ref.x86asm.net/geek64-abc.html
// SYSENTER is 0F 34, SYSCALL is 0F  05, SYSEXIT and SYSRET? HALT? INT $0x80: CD 0x80

#define NOP 0x90
// TODO: endianness?
#define INT_SYSCALL0 0xCD
#define INT_SYSCALL1 0x80
#define SYSCALL0 0x0F
#define SYSCALL1 0x05
#define SYSENTER0 0x0F
#define SYSENTER1 0x34

long my_ptrace(int request, pid_t child, long addr, void *data) {
    long ret = ptrace(request, child, addr, data);
    if (ret == -1) {
    	perror("Uh oh!");
    	kill(child, SIGKILL);
    	exit(1);
    }
    if (request == PTRACE_TRACEME || request == PTRACE_SYSCALL || request == PTRACE_SYSEMU) {
	int status;
	wait(&status);
	if (WIFEXITED(status)) {
	    exit(0);
	}
    }
    return ret;
}

// TODO: separate PEEKTEXT and PEEK_DATA
static inline void get_put_data(pid_t child, long addr, void *bytes, size_t len, bool get_data) {
    while (len >= sizeof(long)) {
    	if (get_data) {
	    *(long *)bytes = my_ptrace(PTRACE_PEEKTEXT, child, addr, NULL);
	} else {
	    my_ptrace(PTRACE_POKEDATA, child, addr, bytes);
	}
	len -= sizeof(long);
	bytes += sizeof(long);
	addr += sizeof(long);
    }
    // TODO: should we just disallow this altogether?
    if (len != 0) {
    	unsigned char data[sizeof(long)];
	*(long *)data = my_ptrace(PTRACE_PEEKTEXT, child, addr, NULL);
	if (get_data) {
	    memcpy(bytes, data, len);
	} else {
	    // TODO: endianness?
	    memcpy(data, bytes, len);
	    my_ptrace(PTRACE_POKEDATA, child, addr, data);
	}
    }
}

// TODO: this should probably never be used. Ultimately leads to timing exploits maybe?
void syscall_passthrough(pid_t child, struct user_regs_struct regs) {

    // TODO: does anything else need to be reverted?
    // TODO: is this the right number of bytes to go back??
    regs.rip -= 2;
    my_ptrace(PTRACE_POKEUSER, child, sizeof(long) * RIP, &regs.rip);
    my_ptrace(PTRACE_SYSCALL, child, 0, NULL);
    // TODO: which system calls don't return?
    // wait for the return
    if (regs.orig_rax != SYS_exit_group && regs.orig_rax != SYS_execve) {
	my_ptrace(PTRACE_SYSCALL, child, 0, NULL);
	long rax = my_ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RAX, NULL);
	printf("%s returned with %ld\n", syscall_map[regs.orig_rax], rax);
    }
}

void get_data(pid_t child, long addr, void *bytes, size_t len) {
    get_put_data(child, addr, bytes, len, true);
}
void put_data(pid_t child, long addr, const void *bytes, size_t len) {
    get_put_data(child, addr, (void *)bytes, len, false);
}

// TODO: disable core dump?????
// TODO: check for errors (-1 ptrace returns)
int main(int argc, char *const argv[]) {
    pid_t child = fork();
    if (child == 0) {
	ptrace(PTRACE_TRACEME, 0, 0, NULL);
	execl("./test", "ls", NULL);
    }
    int status;
    wait(&status);

    int in_syscall = 0;
    int current_syscall = 0;
    while (true) {
	printf("ugh\n");
	my_ptrace(PTRACE_SYSEMU, child, 0, NULL);

	struct user_regs_struct regs;

	my_ptrace(PTRACE_GETREGS, child, 0, &regs);
	printf("%s at %llx called with %lld, %lld, %lld\n",
		syscall_map[regs.orig_rax], regs.rip, regs.rbx, regs.rcx, regs.rdx);
	if (regs.orig_rax == SYS_read) {
	} else {
	    syscall_passthrough(child, regs);
	}
    }
    return 0;
}
