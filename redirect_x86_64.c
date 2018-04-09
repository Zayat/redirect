#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <errno.h>
#include <error.h>

#define die(s) error(1, errno, "%s: " s, __func__)
typedef unsigned long long int datatype;

typedef uint32_t word_t;
#define word_size sizeof(word_t)

static const char * proc_name;
static char insert_code[] = "\x0f\x05\xcc";

void getdata(pid_t child, const word_t * addr, word_t *str, int len) {
	int i;
	int j = ((len + word_size -1) / word_size);
	for (i = 0; i < j; i++) {
		*str++ = ptrace(PTRACE_PEEKDATA, child, addr++, NULL);
	}
}

void putdata(pid_t child, const word_t * addr, const word_t *str, int len) {
	int i;
	int j = ((len + word_size -1) / word_size);
	for (i = 0; i < j; i++) {
		ptrace(PTRACE_POKEDATA, child, addr++, *str++);
	}
}

size_t calculate_size(const char * outpath) {
	size_t result = strlen(outpath) + 1
			+ sizeof(insert_code);
	result += (result % word_size);
	return result;
}

int redirect_output(pid_t pid, int fd, const char * outpath) {
	struct user_regs_struct regs;
	struct user_regs_struct oldregs;
	size_t size = calculate_size(outpath);
	void * backup;
	size_t outpath_len = strlen(outpath)+1;
	void * addr = NULL;
	int rc = 0;
	int cnt;
	printf("Enter redirect output. pid: %u, fd: %d, size: %lu\n", pid, fd, size);

	rc = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (rc) {
		die("attach");
	}
	waitpid(pid, NULL, 0);
	printf("Attached: %d\n", rc);

	rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	if (rc) {
		die("getregs");
	}
	printf("Got registers: %d\n", rc);
	addr = (void*)regs.rip;
	backup = alloca(size);
	getdata(pid, addr, backup, size);
	printf("Backed up memory\n");

	printf("Putting data %lu:\n", size);
	for (cnt=0; cnt < outpath_len; cnt++) {
		printf("0x%x ", outpath[cnt] & 0xff);
	}
	printf("\n");
	for (cnt=0; cnt < size-outpath_len; cnt++) {
		printf("0x%x ", insert_code[cnt] & 0xff);
	}
	printf("\n");
	void * data = alloca(size);
	memset(data, 0, size);
	memcpy(data, outpath, outpath_len);
	memcpy(data+outpath_len, insert_code, sizeof(insert_code));
	putdata(pid, addr, data, size);

	char * temp = alloca(size);
	memset(temp, 0, size);
	getdata(pid, addr, (word_t*)temp, size);
	printf("New data %lu:\n", size);
	for (cnt=0; cnt < size; cnt++) {
		printf("0x%x ", temp[cnt] & 0xff);
	}
	printf("\n");


	memcpy(&oldregs, &regs, sizeof(regs));

	regs.rip = (datatype)(addr+outpath_len);
	regs.rax = 2; /* Open */
	regs.rdi = (datatype)addr;
	regs.rsi = O_WRONLY | O_CREAT;
	regs.rdx = S_IRWXU | S_IRWXG | S_IRWXO; /* mode */
	rc = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	if (rc) {
		die("setregs");
	}
	rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
	if (rc) {
		die("cont");
	}
	waitpid(pid, NULL, 0);
	rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	if (rc) {
		die("getregs (2)");
	}
	printf("Open: %d, %llu\n", rc, regs.rax);
	if (regs.rax > -4096u) {
		fprintf(stderr, "Open: %s\n", strerror(-regs.rax));
	}

	regs.rip = (datatype)(addr+outpath_len);
	regs.rdi = regs.rax;
	regs.rax = 33; /* dup2 */
	regs.rsi = fd;
	rc = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	if (rc) {
		die("setregs (2)");
	}
	rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
	if (rc) {
		die("cont (2)");
	}
	waitpid(pid, NULL, 0);
	rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	if (rc) {
		die("getregs (3)");
	}
	printf("Dup: %d, %llu\n", rc, regs.rax);
	if (regs.rax > -4096u) {
		fprintf(stderr, "Dup: %s\n", strerror(-regs.rax));
	}

	regs.rip = (datatype)(addr+outpath_len);
	regs.rax = 3; /* close */
	rc = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	if (rc) {
		die("setregs (4)");
	}
	rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
	if (rc) {
		die("cont (4)");
	}
	waitpid(pid, NULL, 0);
	rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	if (rc) {
		die("getregs (4)");
	}
	printf("Close: %d, %llu\n", rc, regs.rax);
	if (regs.rax) {
		fprintf(stderr, "Close: %s\n", strerror(-regs.rax));
	}
	
	putdata(pid, addr, backup, size);
	printf("Reverted data\n");
	rc = ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);
	if (rc) {
		die("reset regs");
	}
	printf("Reset registers: %d\n", rc);
	rc = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (rc) {
		die("detach");
	}
	printf("Detached: %d\n", rc);
	return 0;
}

int redirect_output_by_strings(
		const char * pid_str,
		const char * fd_str,
		const char * outpath) {
	int pid;
	int fd;
	errno = 0;
	pid = strtol(pid_str, NULL, 10);
	if (errno) {
		die("Invalid pid: ");
		return 1;
	}
	fd = strtol(fd_str, NULL, 10);
	if (errno) {
		die("Invalid fd: ");
		return 1;
	}
	return redirect_output(pid, fd, outpath);
}


int main(int argc, char * argv[]) {
	proc_name = argv[0];
	if (argc != 4) {
		fprintf(stderr, "%s: Usage: %s <pid> <fd> <new outpath>\n",
				proc_name, proc_name);
		exit(1);
	}
	return redirect_output_by_strings(argv[1], argv[2], argv[3]);
}

