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

typedef unsigned long long int datatype;
#define datatype_size sizeof(datatype)

typedef uint32_t word_t;
#define word_size sizeof(word_t)

static const char * proc_name;
static char insert_code[] = "\x0f\x05\xcc";

void * get_free_space_addr(pid_t pid) {
	FILE *fp;
	char filename[30];
	char line[85];
	void * addr;
	char str[20];
	snprintf(filename, 30, "/proc/%d/maps", pid);
	fp = fopen(filename, "r");
	if(fp == NULL) {
		return NULL;
	}
	while(fgets(line, 85, fp) != NULL) {
		sscanf(line, "%lx-%*lx %*s %*s %s", &addr, str);
		if(strcmp(str, "00:00") == 0) {
			break;
		}
		addr = NULL;
	}
	fclose(fp);
	return addr;
}

void getdata(pid_t child, void * addr, char *str, int len) {
	char *laddr;
	int i, j;
	union u {
			word_t val;
			char chars[word_size];
	}data;
	i = 0;
	j = len / word_size;
	laddr = str;
	while(i < j) {
		data.val = ptrace(PTRACE_PEEKDATA, child,
						  addr + i * 4, NULL);
		memcpy(laddr, data.chars, word_size);
		++i;
		laddr = ((char*)laddr) + word_size;
	}
	j = len % word_size;
	if(j != 0) {
		data.val = ptrace(PTRACE_PEEKDATA, child,
						  addr + i * 4, NULL);
		memcpy(laddr, data.chars, j);
	}
	str[len] = '\0';
}

void putdata(pid_t child, const void * addr, const char *str, int len) {
	const char *laddr;
	int i;
	int j;
	union u {
			word_t val;
			char chars[word_size];
	} data;
	i = 0;
	j = len / word_size;
	laddr = str;
	while(i < j) {
		memcpy(data.chars, laddr, word_size);
		ptrace(PTRACE_POKEDATA, child,
				addr + i * 4, data.val);
		++i;
		laddr += word_size;
	}
	j = len % word_size;
	if(j != 0) {
		memcpy(data.chars, laddr, j);
		ptrace(PTRACE_POKEDATA, child,
			   addr + i * 4, data.val);
	}
}

size_t calculate_size(const char * outpath) {
	size_t result = strlen(outpath) + 1
			+ sizeof(insert_code);
	return result;
}

int redirect_output(pid_t pid, int fd, const char * outpath) {
	struct user_regs_struct regs;
	struct user_regs_struct oldregs;
	size_t size = calculate_size(outpath);
	void * backup;
	size_t outpath_len = strlen(outpath)+1;
//	void * addr = get_free_space_addr(pid);
	void * addr = NULL; //= get_free_space_addr(pid);
	int rc = 0;
	int cnt;
	printf("Enter redirect output. pid: %u, fd: %d, size: %u, %p\n", pid, fd, size, addr);

	rc = ptrace(PTRACE_ATTACH, pid, NULL, NULL);
	if (rc) {
		perror("attach");
	}
	wait(NULL);
	printf("Attached: %d\n", rc);

	rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	if (rc) {
		perror("getregs");
	}
	printf("Got registers: %d\n", rc);
	addr = (void*)regs.rip;
	backup = malloc(size);
	getdata(pid, addr, backup, size);
	printf("Backed up memory\n");

	printf("Putting data %u:\n", size);
	for (cnt=0; cnt < outpath_len; cnt++) {
		printf("0x%x ", outpath[cnt] & 0xff);
	}
	printf("\n");
	for (cnt=0; cnt < size-outpath_len; cnt++) {
		printf("0x%x ", insert_code[cnt] & 0xff);
	}
	printf("\n");
	putdata(pid, addr, outpath, outpath_len);
	putdata(pid, addr+outpath_len, insert_code, sizeof(insert_code));
	memcpy(&oldregs, &regs, sizeof(regs));

	regs.rip = (datatype)(addr+outpath_len);
	regs.rax = 2; /* Open */
	regs.rdi = (datatype)addr;
	regs.rsi = O_WRONLY | O_CREAT;
	regs.rdx = S_IRWXU | S_IRWXG | S_IRWXO; /* mode, ignored */
	rc = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	if (rc) {
		perror("setregs");
	}
	rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
	if (rc) {
		perror("cont");
	}
	wait(NULL);
	rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	if (rc) {
		perror("getregs (2)");
	}
	printf("Open: %d, %d\n", rc, regs.rax);
	if (regs.rax > -4096u) {
		fprintf(stderr, "Open: %s\n", strerror(-regs.rax));
	}

	regs.rip = (datatype)(addr+outpath_len);
	regs.rdi = regs.rax;
	regs.rax = 33; /* dup2 */
	regs.rsi = fd;
	rc = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	if (rc) {
		perror("setregs (2)");
	}
	rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
	if (rc) {
		perror("cont (2)");
	}
	wait(NULL);
	rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	if (rc) {
		perror("getregs (3)");
	}
	printf("Dup: %d, %d\n", rc, regs.rax);
	if (regs.rax > -4096u) {
		fprintf(stderr, "Dup: %s\n", strerror(-regs.rax));
	}

	regs.rip = (datatype)(addr+outpath_len);
	regs.rax = 3; /* close */
	rc = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	if (rc) {
		perror("setregs (4)");
	}
	rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
	if (rc) {
		perror("cont (4)");
	}
	wait(NULL);
	rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	if (rc) {
		perror("getregs (4)");
	}
	printf("Close: %d, %d\n", rc, regs.rax);
	if (regs.rax) {
		fprintf(stderr, "Close: %s\n", strerror(-regs.rax));
	}
	
	putdata(pid, addr, backup, size);
	printf("Reverted data\n");
	free(backup);
	rc = ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);
	if (rc) {
		perror("reset regs");
	}
	printf("Reset registers: %d\n", rc);
	rc = ptrace(PTRACE_DETACH, pid, NULL, NULL);
	if (rc) {
		perror("detach");
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
	int cnt;
	errno = 0;
	pid = strtol(pid_str, NULL, 10);
	if (errno) {
		perror("Invalid pid: ");
		return 1;
	}
	fd = strtol(fd_str, NULL, 10);
	if (errno) {
		perror("Invalid fd: ");
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

