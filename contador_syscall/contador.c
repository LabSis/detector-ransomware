#include <linux/module.h>  /* Needed by all kernel modules */
#include <linux/kernel.h>  /* Needed for loglevels (KERN_WARNING, KERN_EMERG, KERN_INFO, etc.) */
#include <linux/init.h>    /* Needed for __init and __exit macros. */
#include <linux/unistd.h>  /* sys_call_table __NR_* system call function indices */
#include <linux/fs.h>      /* filp_open */
#include <linux/slab.h>    /* kmalloc */
#include <linux/sched.h>

#include <asm/paravirt.h> /* write_cr0 */
#include <asm/uaccess.h>  /* get_fs, set_fs */

#include "contador.h"

#define PROC_V    "/proc/version"
#define BOOT_PATH "/boot/System.map-"
#define MAX_VERSION_LEN   256
#define MAX_ARRAY_LENGTH 300
#define THRESHOLD 20000

unsigned long *syscall_table = NULL;
//unsigned long *syscall_table = (unsigned long *)0xffffffff81801400;


int processes[MAX_ARRAY_LENGTH];
int write_count[MAX_ARRAY_LENGTH];
int read_count[MAX_ARRAY_LENGTH];
int index = 0;

asmlinkage long (*original_write)(unsigned int, const char __user *, size_t);
asmlinkage long (*original_read)(unsigned int, const char __user *, size_t);

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
             
                //syscall_table = (unsigned long long *) kstrtoll(sys_string, NULL, 16);
                //syscall_table = kmalloc(sizeof(unsigned long *), GFP_KERNEL);
                //syscall_table = kmalloc(sizeof(syscall_table), GFP_KERNEL);
                kstrtoul(sys_string, 16, &syscall_table);
                //printk(KERN_INFO "syscall_table retrieved\n");
                 
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

asmlinkage long new_read (unsigned int x, const char __user *y, size_t size) {
    int pid = current->pid;
	char *name = current->comm;
	int ok = 0;
	int i = 0;
	for (i = 0; i < index; i++) {
        if (processes[i] == pid) {
            read_count[i]++;
            if (read_count[i] > THRESHOLD) {
                /*int signum = SIGKILL;
                struct siginfo info;
                memset(&info, 0, sizeof(struct siginfo));
                info.si_signo = signum;
                int ret = send_sig_info(signum, &info, current);
                if (ret < 0) {
                  printk(KERN_INFO "error sending signal\n");
                }*/
                printk(KERN_EMERG "MUCHAS LECTURAS. PROCESO: %s = %d", name, read_count[i]);
            }
            ok = 1;
            break;
        }
    }
    if (ok == 0) {
        if (index < MAX_ARRAY_LENGTH) {
            processes[index] = pid;
            read_count[index]++;
            if (read_count[index] > THRESHOLD) {
                /*int signum = SIGKILL;
                struct siginfo info;
                memset(&info, 0, sizeof(struct siginfo));
                info.si_signo = signum;
                int ret = send_sig_info(signum, &info, current);
                if (ret < 0) {
                  printk(KERN_INFO "error sending signal\n");
                }*/
                printk(KERN_EMERG "MUCHAS LECTURAS. PROCESO: %s = %d", name, read_count[i]);
            }
            index++;
            ok = 1;
        } else {
            printk(KERN_EMERG "No queda espacio en el array");
        }
    }

    return original_read(x, y, size);
}

asmlinkage long new_write (unsigned int x, const char __user *y, size_t size) {
	int pid = current->pid;
	char *name = current->comm;
	int ok = 0;
	int i = 0;
	for (i = 0; i < index; i++) {
        if (processes[i] == pid) {
            write_count[i]++;
            if (write_count[i] > THRESHOLD) {
                /*int signum = SIGKILL;
                struct siginfo info;
                memset(&info, 0, sizeof(struct siginfo));
                info.si_signo = signum;
                int ret = send_sig_info(signum, &info, current);
                if (ret < 0) {
                  printk(KERN_INFO "error sending signal\n");
                }*/
                printk(KERN_EMERG "MUCHAS ESCRITURAS. PROCESO: %s = %d", name, write_count[i]);
            }
            ok = 1;
            break;
        }
    }
    if (ok == 0) {
        if (index < MAX_ARRAY_LENGTH) {
            processes[index] = pid;
            write_count[index]++;
            if (write_count[index] > THRESHOLD) {
                /*int signum = SIGKILL;
                struct siginfo info;
                memset(&info, 0, sizeof(struct siginfo));
                info.si_signo = signum;
                int ret = send_sig_info(signum, &info, current);
                if (ret < 0) {
                  printk(KERN_INFO "error sending signal\n");
                }*/
                printk(KERN_EMERG "MUCHAS ESCRITURAS. PROCESO: %s = %d", name, write_count[i]);
            }
            index++;
            ok = 1;
        } else {
            printk(KERN_EMERG "No queda espacio en el array");
        }
    }

    return original_write(x, y, size);
}

static int __init onload(void) {
    int i = 0;
    char *kernel_version = kmalloc(MAX_VERSION_LEN, GFP_KERNEL);
    //printk(KERN_WARNING "Hello world!\n");
    // printk(KERN_INFO "Version: %s\n", acquire_kernel_version(kernel_version));
  
    find_sys_call_table(acquire_kernel_version(kernel_version));
  
    /*printk(KERN_INFO "Syscall table address: %p\n", syscall_table);
    printk(KERN_INFO "sizeof(unsigned long *): %zx\n", sizeof(unsigned long*));
    printk(KERN_INFO "sizeof(sys_call_table) : %zx\n", sizeof(syscall_table));*/
  
    if (syscall_table != NULL) {
        write_cr0 (read_cr0 () & (~ 0x10000));
        original_write = (void *)syscall_table[__NR_write];
        original_read = (void *)syscall_table[__NR_read];
        syscall_table[__NR_write] = &new_write;
        syscall_table[__NR_read] = &new_read;
        write_cr0 (read_cr0 () | 0x10000);
        printk(KERN_INFO "Detector de Ransomware activado\n");
    } else {
        printk(KERN_INFO "Error al detectar la syscall table\n");
    }
  
    kfree(kernel_version);
  
    for (i = 0; i < MAX_ARRAY_LENGTH; i++) {
        processes[i] = -1;
        write_count[i] = 0;
        read_count[i] = 0;
    }
  
    /*
     * A non 0 return means init_module failed; module can't be loaded.
     */
    return 0;
}

static void __exit onunload(void) {
    if (syscall_table != NULL) {
        write_cr0 (read_cr0 () & (~ 0x10000));
        syscall_table[__NR_write] = original_write;
        syscall_table[__NR_read] = original_read;
        write_cr0 (read_cr0 () | 0x10000);
        printk(KERN_INFO "Detector de Ransomware desactivado\n");
    } else {
        printk(KERN_INFO "Error al desactivar el detector de Ransomware\n");
    }

    //printk(KERN_INFO "Goodbye world!\n");
}

module_init(onload);
module_exit(onunload);
