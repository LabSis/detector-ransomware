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

asmlinkage int (*original_mmap)(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
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

int newProcess(void) {
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
	return write_counts[index_process] > THRESHOLD && read_counts[index_process] > THRESHOLD;
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
	killed_process[index_process] = 1;
	processes_name[index_process] = NULL;
	printk(KERN_INFO "¡¡¡Destruyendo proceso!!!: %d (writes: %d, reads: %d)\n", processes[index_process], write_counts[index_process], read_counts[index_process]);
	write_counts[index_process] = 0;
	read_counts[index_process] = 0;
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
		indexProcess = newProcess();
		if (indexProcess != -1) {
			other_counts[indexProcess]++;
		}
	}
}

asmlinkage void *new_mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset){
	updateOtherCounts();
	return original_mmap(addr, length, prot, flags, fd, offset);
}

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
	int killed = 0;
	int i = 0;
	int indexProcess = findIndexProcessByPid(pid);
	if (indexProcess != -1) {
		// If exists already
		write_counts[indexProcess]++;
	} else {
		// If not exist
		indexProcess = newProcess();
		if (indexProcess != -1) {
			write_counts[indexProcess]++;
		}
	}

	if (indexProcess != -1) {
		writes_size[indexProcess] += size;
		int be_should = be_should_kill_it(indexProcess);
		if (be_should == 1) {
			kill_current_process(indexProcess);
			killed = 1;
		}
	}
	total_sys_call++;
	if (total_sys_call % REPORT_COUNT_SYS_CALL == 0) {
		report();
	}

	/*if (killed == 0) {

	}*/
	return original_write(fd, bytes, size);
}

asmlinkage int *new_read(int fd, void *buf, size_t count) {
	int pid = current->pid;
	int killed = 0;
	int i = 0;
	int indexProcess = findIndexProcessByPid(pid);
	if (indexProcess != -1) {
		// If exists already
		read_counts[indexProcess]++;
	} else {
		// If not exist
		indexProcess = newProcess();
		if (indexProcess != -1) {
			read_counts[indexProcess]++;
		}
	}

	if (indexProcess != -1) {
		reads_size[indexProcess] += count;
		int be_should = be_should_kill_it(indexProcess);
		if (be_should == 1) {
			kill_current_process(indexProcess);
			killed = 1;
		}
	}
	total_sys_call++;
	if (total_sys_call % REPORT_COUNT_SYS_CALL == 0) {
		report();
	}

	/*if (killed == 0) {

	}*/
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
	return original_getuid();
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

		original_mmap = (void *)syscall_table[__NR_mmap];
		syscall_table[__NR_mmap] = &new_mmap;

        original_lseek = (void *)syscall_table[__NR_lseek];
        syscall_table[__NR_lseek] = &new_lseek;

        original_close = (void *)syscall_table[__NR_close];
        syscall_table[__NR_close] = &new_close;

        original_fstat = (void *)syscall_table[__NR_fstat];
        syscall_table[__NR_fstat] = &new_fstat;

        original_openat = (void *)syscall_table[__NR_openat];
        syscall_table[__NR_openat] = &new_openat;

        original_stat = (void *)syscall_table[__NR_stat];
        syscall_table[__NR_stat] = &new_stat;

        original_write = (void *)syscall_table[__NR_write];
        syscall_table[__NR_write] = &new_write;

        original_read = (void *)syscall_table[__NR_read];
        syscall_table[__NR_read] = &new_read;

        /*original_kill = (void *)syscall_table[__NR_kill];
        syscall_table[__NR_kill] = &new_kill;

        original_exit = (void *)syscall_table[__NR_exit];
        syscall_table[__NR_exit] = &new_exit;*/

        original_set_robust_list = (void *)syscall_table[__NR_set_robust_list];
        syscall_table[__NR_set_robust_list] = &new_set_robust_list;

        original_getuid = (void *)syscall_table[__NR_getuid];
        syscall_table[__NR_getuid] = &new_getuid;

        original_geteuid = (void *)syscall_table[__NR_geteuid];
        syscall_table[__NR_geteuid] = &new_geteuid;

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
        syscall_table[__NR_mmap] = original_mmap;
        syscall_table[__NR_lseek] = original_lseek;
        syscall_table[__NR_close] = original_close;
        syscall_table[__NR_fstat] = original_fstat;
        syscall_table[__NR_openat] = original_openat;
        syscall_table[__NR_stat] = original_stat;
        syscall_table[__NR_write] = original_write;
        syscall_table[__NR_read] = original_read;
        /*syscall_table[__NR_kill] = original_kill;
        syscall_table[__NR_exit] = original_exit;*/
        syscall_table[__NR_set_robust_list] = original_set_robust_list;
        syscall_table[__NR_getuid] = original_getuid;
        syscall_table[__NR_geteuid] = original_geteuid;
        write_cr0 (read_cr0 () | 0x10000);
        printk(KERN_INFO "Detector de Ransomware desactivado\n");
    } else {
        printk(KERN_INFO "Error al desactivar el detector de Ransomware\n");
    }
}

module_init(onload);
module_exit(onunload);
