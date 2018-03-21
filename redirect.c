#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <fcntl.h>
#include <errno.h>

static const char * proc_name;
static char insert_code[] = "\xcd\x80\xcc";

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

#define long_size sizeof(long)
void getdata(pid_t child, void * addr, char *str, int len) {
	char *laddr;
	int i, j;
	union u {
			long val;
			char chars[long_size];
	}data;
	i = 0;
	j = len / long_size;
	laddr = str;
	while(i < j) {
		data.val = ptrace(PTRACE_PEEKDATA, child,
						  addr + i * 4, NULL);
		memcpy(laddr, data.chars, long_size);
		++i;
		laddr = ((char*)laddr) + long_size;
	}
	j = len % long_size;
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
			long val;
			char chars[long_size];
	} data;
	i = 0;
	j = len / long_size;
	laddr = str;
	while(i < j) {
		memcpy(data.chars, laddr, long_size);
		ptrace(PTRACE_POKEDATA, child,
				addr + i * 4, data.val);
		++i;
		laddr += long_size;
	}
	j = len % long_size;
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
	wait(NULL);
	printf("Attached: %d\n", rc);

	rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	printf("Got registers: %d\n", rc);
	addr = (void*)regs.eip;
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
	putdata(pid, addr+outpath_len, insert_code, size-outpath_len);
	memcpy(&oldregs, &regs, sizeof(regs));

	regs.eip = (long)(addr+outpath_len);
	regs.eax = 5; /* Open */
	regs.ebx = (long)addr;
	regs.ecx = 1; /* O_WRONLY */
	regs.edx = 0; /* mode, ignored */
	rc = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
	wait(NULL);
	rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	printf("Open: %d, %d\n", rc, regs.eax);

	regs.eip = (long)(addr+outpath_len);
	regs.ebx = regs.eax;
	regs.eax = 0x3f; /* dup2 */
	regs.ecx = fd;
	rc = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
	wait(NULL);
	rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	printf("Dup: %d, %d\n", rc, regs.eax);

	regs.eip = (long)(addr+outpath_len);
	regs.eax = 6; /* close */
	rc = ptrace(PTRACE_SETREGS, pid, NULL, &regs);
	rc = ptrace(PTRACE_CONT, pid, NULL, NULL);
	wait(NULL);
	rc = ptrace(PTRACE_GETREGS, pid, NULL, &regs);
	printf("Close: %d, %d\n", rc, regs.eax);
	
	putdata(pid, addr, backup, size);
	printf("Reverted data\n");
	free(backup);
	rc = ptrace(PTRACE_SETREGS, pid, NULL, &oldregs);
	printf("Reset registers: %d\n", rc);
	rc = ptrace(PTRACE_DETACH, pid, NULL, NULL);
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

