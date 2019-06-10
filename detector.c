#include <linux/module.h>  /* Needed by all kernel modules */
#include <linux/kernel.h>  /* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>    /* Needed for __init and __exit macros. */
#include <linux/unistd.h>  /* sys_call_table __NR_* system call function indices */
#include <linux/fs.h>      /* filp_open */
#include <linux/slab.h>    /* kmalloc */
#include <linux/sched.h>
#include <asm/paravirt.h> /* write_cr0 */
#include <asm/uaccess.h>  /* get_fs, set_fs */

#include "detector.h"

#define PROC_V    "/proc/version"
#define BOOT_PATH "/boot/System.map-"
#define MAX_VERSION_LEN   256
#define MAX_PROCESS_COUNT 1000
#define THRESHOLD 500000
#define REPORT_COUNT_SYS_CALL 10000

unsigned long *syscall_table = NULL;

int processes[MAX_PROCESS_COUNT];
int write_counts[MAX_PROCESS_COUNT];
int read_counts[MAX_PROCESS_COUNT];
unsigned long long writes_size[MAX_PROCESS_COUNT];
unsigned long long reads_size[MAX_PROCESS_COUNT];
int other_counts[MAX_PROCESS_COUNT];
int killed_process[MAX_PROCESS_COUNT];
char *processes_name[MAX_PROCESS_COUNT];

int last_index_process = -1;
long total_sys_call = 0;

asmlinkage int (*original_access)(const char *pathname, int mode);
asmlinkage int (*original_munmap)(void *addr, size_t length);
asmlinkage int (*original_getdents)(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
asmlinkage int (*original_newfstatat)(int dirfd, const char *pathname, struct stat *statbuf, int flags);
asmlinkage int (*original_ioctl)(int fd, unsigned long request, char *argv);
asmlinkage int (*original_fcntl)(int fd, int cmd, char *argv);
/*asmlinkage ssize_t (*original_sendto)(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen);
 * asmlinkage int (*original_poll)(struct pollfd *fds, nfds_t nfds, int timeout);
asmlinkage int (*original_epoll_wait)(int epfd, struct epoll_event *events, int maxevents, int timeout);*/
asmlinkage ssize_t (*original_recvmsg)(int sockfd, struct msghdr *msg, int flags);
asmlinkage pid_t (*original_gettid)(void);
asmlinkage int (*original_mprotect)(void *addr, size_t len, int prot);
asmlinkage int (*original_brk)(void *addr);
asmlinkage int (*original_getdents64)(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
/*asmlinkage void* (*original_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);*/
asmlinkage int (*original_lseek)(int fd, off_t offset, int whence);
asmlinkage int (*original_close)(int fd);
asmlinkage int (*original_fstat)(int fd, struct stat *buf);
asmlinkage int (*original_openat)(int dirfd, const char *pathname, int flags, mode_t mode);
asmlinkage int (*original_stat)(const char __user *filename, struct stat __user *statbuf);
asmlinkage int (*original_write)(unsigned int, const char __user *, size_t);
asmlinkage int (*original_read)(int fd, void *buf, size_t count);
asmlinkage int (*original_kill)(pid_t pid, int sig);
asmlinkage int (*original_exit)(int status);
asmlinkage long (*original_set_robust_list)(struct robust_list_head *head, size_t len);
asmlinkage uid_t (*original_getuid)(void);
asmlinkage uid_t (*original_geteuid)(void);
asmlinkage gid_t (*original_getgid)(void);
asmlinkage gid_t (*original_getegid)(void);
/*asmlinkage int (*original_execve)(const char *pathname, char *const argv[], char *const envp[]);*/
asmlinkage ssize_t (*original_getrandom)(void *buf, size_t buflen, unsigned int flags);
asmlinkage int (*original_rt_sigprocmask)(int how, const sigset_t *set, sigset_t *oldset);
asmlinkage int (*original_clock_gettime)(clockid_t clk_id, struct timespec *tp);
asmlinkage int (*original_dup)(int oldfd);

static int find_sys_call_table (char *kern_ver) {
    char system_map_entry[MAX_VERSION_LEN];
    int i = 0;

    /*
     * Holds the /boot/System.map-<version> file name as we build it
     */
    char *filename;

    /*
     * Length of the System.map filename, terminating NULL included
     */
    size_t filename_length = strlen(kern_ver) + strlen(BOOT_PATH) + 1;

    /*
     * This will point to our /boot/System.map-<version> file
     */
    struct file *f = NULL;
 
    mm_segment_t oldfs;
 
    oldfs = get_fs();
    set_fs (KERNEL_DS);

    printk(KERN_INFO "Kernel version: %s\n", kern_ver);
     
    filename = kmalloc(filename_length, GFP_KERNEL);
    if (filename == NULL) {
        printk(KERN_INFO "kmalloc failed on System.map-<version> filename allocation");
        return -1;
    }
     
    /*
     * Zero out memory to be safe
     */
    memset(filename, 0, filename_length);
     
    /*
     * Construct our /boot/System.map-<version> file name
     */
    strncpy(filename, BOOT_PATH, strlen(BOOT_PATH));
    strncat(filename, kern_ver, strlen(kern_ver));
     
    /*
     * Open the System.map file for reading
     */
    f = filp_open(filename, O_RDONLY, 0);
    if (IS_ERR(f) || (f == NULL)) {
        printk(KERN_INFO "Error opening System.map-<version> file: %s\n", filename);
        return -1;
    }
 
    memset(system_map_entry, 0, MAX_VERSION_LEN);
 
    /*
     * Read one byte at a time from the file until we either max out
     * out our buffer or read an entire line.
     */
    while (vfs_read(f, system_map_entry + i, 1, &f->f_pos) == 1) {
        /*
         * If we've read an entire line or maxed out our buffer,
         * check to see if we've just read the sys_call_table entry.
         */
        if ( system_map_entry[i] == '\n' || i == MAX_VERSION_LEN ) {
            // Reset the "column"/"character" counter for the row
            i = 0;
             
            if (strstr(system_map_entry, "sys_call_table") != NULL) {
                char *sys_string;
                char *system_map_entry_ptr = system_map_entry;
                 
                sys_string = kmalloc(MAX_VERSION_LEN, GFP_KERNEL);  
                if (sys_string == NULL) { 
                    filp_close(f, 0);
                    set_fs(oldfs);

                    kfree(filename);
     
                    return -1;
                }
                memset(sys_string, 0, MAX_VERSION_LEN);
                strncpy(sys_string, strsep(&system_map_entry_ptr, " "), MAX_VERSION_LEN);
                kstrtoul(sys_string, 16, &syscall_table);
                kfree(sys_string);

                break;
            }
            memset(system_map_entry, 0, MAX_VERSION_LEN);
            continue;
        }
        i++;
    }

    filp_close(f, 0);
    set_fs(oldfs);
    kfree(filename);

    return 0;
}

/*
 * We have to pass in a pointer to a buffer to store the parsed
 * version information in. If we declare a pointer to the
 * parsed version info on the stack of this function, the
 * pointer will disappear when the function ends and the
 * stack frame is removed.
 */
char *acquire_kernel_version (char *buf) {
    struct file *proc_version;
    char *kernel_version;
  
    /*
     * We use this to store the userspace perspective of the filesystem
     * so we can switch back to it after we are done reading the file
     * into kernel memory
     */
    mm_segment_t oldfs;
  
    /*
     * Standard trick for reading a file into kernel space
     * This is very bad practice. We're only doing it here because
     * we're malicious and don't give a damn about best practices.
     */
    oldfs = get_fs();
    set_fs (KERNEL_DS);
  
    /*
     * Open the version file in the /proc virtual filesystem
     */
    proc_version = filp_open(PROC_V, O_RDONLY, 0);
    if (IS_ERR(proc_version) || (proc_version == NULL)) {
        return NULL;
    }
  
    /*
     * Zero out memory just to be safe
     */
    memset(buf, 0, MAX_VERSION_LEN);
  
    /*
     * Read version info from /proc virtual filesystem
     */
    vfs_read(proc_version, buf, MAX_VERSION_LEN, &(proc_version->f_pos));
  
    /*
     * Extract the third field from the full version string
     */
    kernel_version = strsep(&buf, " ");
    kernel_version = strsep(&buf, " ");
    kernel_version = strsep(&buf, " ");
  
    filp_close(proc_version, 0);
    
    /*
     * Switch filesystem context back to user space mode
     */
    set_fs(oldfs);
  
    return kernel_version;
}

int findIndexProcessByPid(int pid) {
	int i = 0;
	int index = -1;
	for (i = 0; i <= last_index_process; i++) {
		if (killed_process[i] == 0 && processes[i] == pid) {
			index = i;
			break;
		}
	}
	return index;
}

int new_process(void) {
	int i = 0;
	int index = -1;
	// Search killed process
	for (i = 0; i <= last_index_process; i++) {
		if (killed_process[i] == 1) {
			// Is dead
			index = i;
			killed_process[i] = 0;
			break;
		}
	}
	if (index == -1) {
		last_index_process++;
		index = last_index_process;
	}
	if (last_index_process < MAX_PROCESS_COUNT) {
		processes[index] = current->pid;
		processes_name[index] = current->comm;
	} else {
		printk(KERN_INFO "Error, no hay suficiente espacio en la tabla de procesos.\n");
	}

	return index;
}

int be_should_kill_it(int index_process) {
	return write_counts[index_process] > THRESHOLD &&
			read_counts[index_process] > THRESHOLD &&
			write_counts[index_process] > other_counts[index_process] * 2 &&
			read_counts[index_process] > other_counts[index_process] * 2;
}

void clear_process_data(int index_process) {
	write_counts[index_process] = 0;
	read_counts[index_process] = 0;
	other_counts[index_process] = 0;
	writes_size[index_process] = 0;
	reads_size[index_process] = 0;
	killed_process[index_process] = 1;
	processes_name[index_process] = NULL;
}

void kill_current_process(int index_process) {
	int signum = SIGKILL;
	struct siginfo info;
	memset(&info, 0, sizeof(struct siginfo));
	info.si_signo = signum;
	int ret = send_sig_info(signum, &info, current);
	if (ret < 0) {
		printk(KERN_INFO "error sending signal\n");
	}
	printk(KERN_INFO "¡¡¡Destruyendo proceso!!!: %d (writes: %d, reads: %d)\n", processes[index_process], write_counts[index_process], read_counts[index_process]);
	clear_process_data(index_process);
}

void report(void) {
	printk(KERN_INFO "##### Reporte del detector #####\n");
	int i = 0;

	/* Se establece los procesos muertos */
	struct task_struct* task_list;
	for (i = 0; i < last_index_process; i++) {
		if (killed_process[i] == 0) {
			int is_alive = 0;
			for_each_process(task_list) {
				if (processes[i] == task_list->pid) {
					// Is alive
					is_alive = 1;
				}
			}

			if (is_alive == 0) {
				killed_process[i] = 1;
				clear_process_data(i);
			}
		}
	}
	int not_dead_processes = 0;
	int dead_processes = 0;

	for (i = 0; i <= last_index_process; i++) {
		if (killed_process[i] == 0) {
			printk(KERN_INFO "Proceso: %s (%d)", processes_name[i], processes[i]);
			printk(KERN_INFO "Cantidad de escrituras: %d (%llu)", write_counts[i], writes_size[i]);
			printk(KERN_INFO "Cantidad de lecturas: %d (%llu)", read_counts[i], reads_size[i]);
			printk(KERN_INFO "Cantidad de otras: %d", other_counts[i]);
			printk(KERN_INFO "---------------------");
			not_dead_processes++;
		} else {
			printk(KERN_INFO "Proceso - ya muerto: %s (%d)", processes_name[i], processes[i]);
			printk(KERN_INFO "Cantidad de escrituras: %d (%llu)", write_counts[i], writes_size[i]);
			printk(KERN_INFO "Cantidad de lecturas: %d (%llu)", read_counts[i], reads_size[i]);
			printk(KERN_INFO "Cantidad de otras: %d", other_counts[i]);
			printk(KERN_INFO "---------------------");
			dead_processes++;
		}
	}
	int total_processes = not_dead_processes + dead_processes;
	printk(KERN_INFO "(Total, no muertos, muertos) = (%d, %d %d)", total_processes, not_dead_processes, dead_processes);
}

void updateOtherCounts(void){
	int pid = current->pid;
	int indexProcess = findIndexProcessByPid(pid);
	if (indexProcess != -1) {
		// If exists already
		other_counts[indexProcess]++;
	} else {
		// If not exist
		indexProcess = new_process();
		if (indexProcess != -1) {
			other_counts[indexProcess]++;
		}
	}
}

asmlinkage int new_access(const char *pathname, int mode){
	updateOtherCounts();
	return original_access(pathname, mode);
}

asmlinkage int new_munmap(void *addr, size_t length){
	updateOtherCounts();
	return original_munmap(addr, length);
}

asmlinkage int new_getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count){
	updateOtherCounts();
	return original_getdents(fd, dirp, count);
}

asmlinkage int new_newfstatat(int dirfd, const char *pathname, struct stat *statbuf, int flags){
	updateOtherCounts();
	return original_newfstatat(dirfd, pathname, statbuf, flags);
}

asmlinkage int new_ioctl(int fd, unsigned long request, char *argv){
	updateOtherCounts();
	return original_ioctl(fd, request, argv);
}

asmlinkage int new_fcntl(int fd, int cmd, char *argv){
	updateOtherCounts();
	return original_fcntl(fd, cmd, argv);
}

/*
asmlinkage ssize_t new_sendto(int sockfd, const void *buf, size_t len, int flags, const struct sockaddr *dest_addr, socklen_t addrlen){
	updateOtherCounts();
	return original_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}*/

/*
asmlinkage int new_poll(struct pollfd *fds, nfds_t nfds, int timeout){
	updateOtherCounts();
	return original_poll(fds, nfds, timeout);
}

asmlinkage int new_epoll_wait(int epfd, struct epoll_event *events, int maxevents, int timeout){
	updateOtherCounts();
	return original_epoll_wait(epfd, events, maxevents, timeout);
}*/

asmlinkage ssize_t new_recvmsg(int sockfd, struct msghdr *msg, int flags){
	updateOtherCounts();
	return original_recvmsg(sockfd, msg, flags);
}

asmlinkage pid_t new_gettid(void){
	updateOtherCounts();
	return original_gettid();
}

asmlinkage int new_mprotect(void *addr, size_t len, int prot){
	updateOtherCounts();
	return original_mprotect(addr, len, prot);
}

asmlinkage int new_brk(void *addr){
	updateOtherCounts();
	return original_brk(addr);
}

asmlinkage int new_getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count){
	updateOtherCounts();
	return original_getdents64(fd, dirp, count);
}

/*
asmlinkage void *new_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset){
	updateOtherCounts();
	return original_mmap(addr, length, prot, flags, fd, offset);
}*/

asmlinkage off_t new_lseek(int fd, off_t offset, int whence){
	updateOtherCounts();
	return original_lseek(fd, offset, whence);
}

asmlinkage int new_close(int fd){
	updateOtherCounts();
	return original_close(fd);
}

asmlinkage int new_fstat(int fd, struct stat *buf){
	updateOtherCounts();
	return original_fstat(fd, buf);
}

asmlinkage int new_openat(int dirfd, const char *pathname, int flags, mode_t mode){
	updateOtherCounts();
	return original_openat(dirfd, pathname, flags, mode);
}

asmlinkage int new_stat (const char __user * filename, struct stat __user * statbuf) {
	updateOtherCounts();
	return original_stat(filename, statbuf);
}

asmlinkage int new_write (unsigned int fd, const char __user *bytes, size_t size) {
	/*unsigned long rax_value;
	asm("" : "=a"(rax_value));
	printk(KERN_INFO "RAX VALUE: %lu", rax_value);*/
	int pid = current->pid;
	int be_should = 0;
	int indexProcess = findIndexProcessByPid(pid);
	if (indexProcess != -1) {
		// If exists already
		write_counts[indexProcess]++;
	} else {
		// If not exist
		indexProcess = new_process();
		if (indexProcess != -1) {
			write_counts[indexProcess]++;
		}
	}

	if (indexProcess != -1) {
		writes_size[indexProcess] += size;
		be_should = be_should_kill_it(indexProcess);
		if (be_should == 1) {
			kill_current_process(indexProcess);
		}
	}
	total_sys_call++;
	if (total_sys_call % REPORT_COUNT_SYS_CALL == 0) {
		report();
	}

	return original_write(fd, bytes, size);
}

asmlinkage int new_read(int fd, void *buf, size_t count) {
	int pid = current->pid;
	int be_should = 0;
	int indexProcess = findIndexProcessByPid(pid);
	if (indexProcess != -1) {
		// If exists already
		read_counts[indexProcess]++;
	} else {
		// If not exist
		indexProcess = new_process();
		if (indexProcess != -1) {
			read_counts[indexProcess]++;
		}
	}

	if (indexProcess != -1) {
		reads_size[indexProcess] += count;
		be_should = be_should_kill_it(indexProcess);
		if (be_should == 1) {
			kill_current_process(indexProcess);
		}
	}
	total_sys_call++;
	if (total_sys_call % REPORT_COUNT_SYS_CALL == 0) {
		report();
	}

	return original_read(fd, buf, count);
}

/*
asmlinkage int new_kill(pid_t pid, int sig) {
	printk(KERN_INFO "kill(%d)", sig);
	if (sig == SIGKILL) {
		int indexProcess = findIndexProcessByPid(pid);
		if (indexProcess != -1) {
			printk(KERN_INFO "Se murió el proceso: %d", pid);
			killed_process[indexProcess] = 1;
		}
	}
	return original_kill(pid, sig);
}

asmlinkage int new_exit(int status) {
	printk(KERN_INFO "exit(%d)", status);
	int pid = current->pid;
	int indexProcess = findIndexProcessByPid(pid);
	if (indexProcess != -1) {
		printk(KERN_INFO "Se murió el proceso: %d", pid);
		killed_process[indexProcess] = 1;
	}
	return original_exit(status);
}*/

asmlinkage long new_set_robust_list(struct robust_list_head *head, size_t len) {
	updateOtherCounts();
	return original_set_robust_list(head, len);
}

asmlinkage uid_t new_getuid(void) {
	updateOtherCounts();
	return original_getuid();
}

asmlinkage uid_t new_geteuid(void) {
	updateOtherCounts();
	return original_geteuid();
}

asmlinkage gid_t new_getgid(void) {
	updateOtherCounts();
	return original_getgid();
}

asmlinkage gid_t new_getegid(void) {
	updateOtherCounts();
	return original_getegid();
}

/*asmlinkage int new_execve(const char *pathname, char *const argv[], char *const envp[]) {
	updateOtherCounts();
	return original_execve(pathname, argv, envp);
}*/

asmlinkage ssize_t new_getrandom(void *buf, size_t buflen, unsigned int flags) {
	updateOtherCounts();
	return original_getrandom(buf, buflen, flags);
}

asmlinkage int new_rt_sigprocmask(int how, const sigset_t *set, sigset_t *oldset) {
	updateOtherCounts();
	return original_rt_sigprocmask(how, set, oldset);
}

asmlinkage int new_clock_gettime(clockid_t clk_id, struct timespec *tp) {
	updateOtherCounts();
	return original_clock_gettime(clk_id, tp);
}

asmlinkage int new_dup(int oldfd) {
	updateOtherCounts();
	return original_dup(oldfd);
}


static int __init onload(void) {
    int i = 0;

    for (i = 0; i < MAX_PROCESS_COUNT; i++) {
        processes[i] = -1;
        write_counts[i] = 0;
        read_counts[i] = 0;
        other_counts[i] = 0;
        killed_process[i] = 0;
    }

    char *kernel_version = kmalloc(MAX_VERSION_LEN, GFP_KERNEL);

    find_sys_call_table(acquire_kernel_version(kernel_version));

    if (syscall_table != NULL) {
        write_cr0 (read_cr0 () & (~ 0x10000));

        original_access = (void *)syscall_table[__NR_access];
        syscall_table[__NR_access] = (long) &new_access;

        original_munmap = (void *)syscall_table[__NR_munmap];
        syscall_table[__NR_munmap] = (long) &new_munmap;

        original_getdents = (void *)syscall_table[__NR_getdents];
        syscall_table[__NR_getdents] = (long) &new_getdents;

        original_newfstatat = (void *)syscall_table[__NR_newfstatat];
        syscall_table[__NR_newfstatat] = (long) &new_newfstatat;

        original_ioctl = (void *)syscall_table[__NR_ioctl];
        syscall_table[__NR_ioctl] = (long) &new_ioctl;

        original_fcntl = (void *)syscall_table[__NR_fcntl];
        syscall_table[__NR_fcntl] = (long) &new_fcntl;

        /*original_sendto = (void *)syscall_table[__NR_sendto];
        syscall_table[__NR_sendto] = &new_sendto;*/

        /*original_poll = (void *)syscall_table[__NR_poll];
        syscall_table[__NR_poll] = &new_poll;

        original_epoll_wait = (void *)syscall_table[__NR_epoll_wait];
        syscall_table[__NR_epoll_wait] = &new_epoll_wait;*/

		original_recvmsg = (void *)syscall_table[__NR_recvmsg];
        syscall_table[__NR_recvmsg] = (long) &new_recvmsg;

		original_gettid = (void *)syscall_table[__NR_gettid];
        syscall_table[__NR_gettid] = (long) &new_gettid;

        original_mprotect = (void *)syscall_table[__NR_mprotect];
        syscall_table[__NR_mprotect] = (long) &new_mprotect;

        original_brk = (void *)syscall_table[__NR_brk];
        syscall_table[__NR_brk] = (long) &new_brk;

        original_getdents64 = (void *)syscall_table[__NR_getdents64];
		syscall_table[__NR_getdents64] = (long) &new_getdents64;

		/*
		original_mmap = (void *)syscall_table[__NR_mmap];
		syscall_table[__NR_mmap] = &new_mmap;*/

        original_lseek = (void *)syscall_table[__NR_lseek];
        syscall_table[__NR_lseek] = (long) &new_lseek;

        original_close = (void *)syscall_table[__NR_close];
        syscall_table[__NR_close] = (long) &new_close;

        original_fstat = (void *)syscall_table[__NR_fstat];
        syscall_table[__NR_fstat] = (long) &new_fstat;

        original_openat = (void *)syscall_table[__NR_openat];
        syscall_table[__NR_openat] = (long) &new_openat;

        original_stat = (void *)syscall_table[__NR_stat];
        syscall_table[__NR_stat] = (long) &new_stat;

        original_write = (void *)syscall_table[__NR_write];
        syscall_table[__NR_write] = (long) &new_write;

        original_read = (void *)syscall_table[__NR_read];
        syscall_table[__NR_read] = (long) &new_read;

        /*original_kill = (void *)syscall_table[__NR_kill];
        syscall_table[__NR_kill] = &new_kill;

        original_exit = (void *)syscall_table[__NR_exit];
        syscall_table[__NR_exit] = &new_exit;*/

        original_set_robust_list = (void *)syscall_table[__NR_set_robust_list];
        syscall_table[__NR_set_robust_list] = (long) &new_set_robust_list;

        original_getuid = (void *)syscall_table[__NR_getuid];
        syscall_table[__NR_getuid] = (long) &new_getuid;

        original_geteuid = (void *)syscall_table[__NR_geteuid];
        syscall_table[__NR_geteuid] = (long) &new_geteuid;

        original_getgid = (void *)syscall_table[__NR_getgid];
        syscall_table[__NR_getgid] = (long) &new_getgid;

        original_getegid = (void *)syscall_table[__NR_getegid];
        syscall_table[__NR_getegid] = (long) &new_getegid;

        /*original_execve = (void *)syscall_table[__NR_execve];
        syscall_table[__NR_execve] = &new_execve;*/

        original_getrandom = (void *)syscall_table[__NR_getrandom];
        syscall_table[__NR_getrandom] = (long) &new_getrandom;

        /*original_rt_sigprocmask = (void *)syscall_table[__NR_rt_sigprocmask];
        syscall_table[__NR_rt_sigprocmask] = &new_rt_sigprocmask;

        original_clock_gettime = (void *)syscall_table[__NR_clock_gettime];
        syscall_table[__NR_clock_gettime] = &new_clock_gettime;

        original_dup = (void *)syscall_table[__NR_dup];
        syscall_table[__NR_dup] = &new_dup;*/

        write_cr0 (read_cr0 () | 0x10000);
        printk(KERN_INFO "Detector de Ransomware activado\n");
    } else {
        printk(KERN_INFO "Error al detectar la syscall table\n");
    }

    kfree(kernel_version);

    /*
     * A non 0 return means init_module failed; module can't be loaded.
     */
    return 0;
}

static void __exit onunload(void) {
    if (syscall_table != NULL) {
        write_cr0 (read_cr0 () & (~ 0x10000));
        syscall_table[__NR_access] = (long) original_access;
        syscall_table[__NR_munmap] = (long) original_munmap;
        syscall_table[__NR_getdents] = (long) original_getdents;
        syscall_table[__NR_newfstatat] = (long) original_newfstatat;
        syscall_table[__NR_ioctl] = (long) original_ioctl;
        syscall_table[__NR_fcntl] = (long) original_fcntl;
		/*syscall_table[__NR_poll] = original_poll;
		syscall_table[__NR_epoll_wait] = original_epoll_wait;*/
        syscall_table[__NR_recvmsg] = (long) original_recvmsg;
        syscall_table[__NR_gettid] = (long) original_gettid;
        syscall_table[__NR_mprotect] = (long) original_mprotect;
        syscall_table[__NR_brk] = (long) original_brk;
        syscall_table[__NR_getdents64] = (long) original_getdents64;
/*        syscall_table[__NR_mmap] = original_mmap;*/
        syscall_table[__NR_lseek] = (long) original_lseek;
        syscall_table[__NR_close] = (long) original_close;
        syscall_table[__NR_fstat] = (long) original_fstat;
        syscall_table[__NR_openat] = (long) original_openat;
        syscall_table[__NR_stat] = (long) original_stat;
        syscall_table[__NR_write] = (long) original_write;
        syscall_table[__NR_read] = (long) original_read;
        /*syscall_table[__NR_kill] = original_kill;
        syscall_table[__NR_exit] = original_exit;*/
        syscall_table[__NR_set_robust_list] = (long) original_set_robust_list;
        syscall_table[__NR_getuid] = (long) original_getuid;
        syscall_table[__NR_geteuid] = (long) original_geteuid;
        syscall_table[__NR_getgid] = (long) original_getgid;
        syscall_table[__NR_getegid] = (long) original_getegid;
        /*syscall_table[__NR_execve] = original_execve;*/
        syscall_table[__NR_getrandom] = (long) original_getrandom;
        syscall_table[__NR_rt_sigprocmask] = (long) original_rt_sigprocmask;
        syscall_table[__NR_clock_gettime] = (long) original_clock_gettime;
        syscall_table[__NR_dup] = (long) original_dup;

        write_cr0 (read_cr0 () | 0x10000);
        printk(KERN_INFO "Detector de Ransomware desactivado\n");
    } else {
        printk(KERN_INFO "Error al desactivar el detector de Ransomware\n");
    }
}

module_init(onload);
module_exit(onunload);
