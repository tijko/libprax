#include "shadow.h"

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/resource.h>



int is_alive(profile_t *process)
{
    DIR *proc_dir = opendir(PROC);
    struct dirent *cur_proc = malloc(sizeof *cur_proc);
    while ((cur_proc = readdir(proc_dir))) {
        if (cur_proc->d_type ==  DT_DIR && 
            atoi(cur_proc->d_name) == process->pid) {
            closedir(proc_dir);
            return 0;
        }
    }
    closedir(proc_dir);
    return -1;
}

char *construct_path(int pid, char *dir)
{
    char *pid_str = calloc(MAXPID, sizeof(char));
    sprintf(pid_str, "%d", pid);
    size_t dir_len = strlen(dir);
    char *path = calloc(PROCLEN + dir_len + MAXPID, sizeof(char));
    strcat(path, PROC);
    strcat(path, pid_str);
    strcat(path, dir);
    return path;      
}

char *pid_name(profile_t *process)
{
    int alive = is_alive(process);
    if (alive == -1) 
        return NULL;
    char *path = construct_path(process->pid, COMM);
    FILE *proc = fopen(path, "r");
    char *name = NULL;
    size_t n = 0;
    getline(&name, &n, proc);
    fclose(proc);
    name[strlen(name) - 1] = '\0';
    return name;
}

int process_fd_stats(profile_t **process)
{
    char *fullpath;
    char *buf;
    char *fdpath = construct_path((*process)->pid, FD);

    DIR *fd_dir = opendir(fdpath);
    if (!fd_dir) 
        return -1;
    struct dirent *files = malloc(sizeof *files);

    size_t fdpath_len = strlen(fdpath);
    size_t file_len;
    int open_fd;

    (*process)->root = malloc(sizeof((*process)->root));
    fdstats_t **curr = &(*process)->root;
    while ((files = readdir(fd_dir))) {
        if (files->d_type == DT_LNK) {
            file_len = strlen(files->d_name) + 1;
            fullpath = calloc(file_len + fdpath_len, sizeof(char));
            strcat(fullpath, fdpath);
            strcat(fullpath, files->d_name);
            (*curr)->file = NULL;
            open_fd = open(fullpath, O_RDONLY);
            if (open_fd != -1) {
                buf = calloc(sizeof(char) * LINKBUFSIZ, sizeof(char));
                readlink(fullpath, buf, LINKBUFSIZ);
                (*curr)->file = buf;
                (*curr)->file_stats = malloc(sizeof(struct stat));
                fstat(open_fd, (*curr)->file_stats);
                curr = &(*curr)->next_fd;
                *curr = malloc(sizeof **curr);
            }
            free(fullpath);
        }
    }
    return 0;
}

int get_pid_nice(profile_t *process)
{
    int nice_value = getpriority(PRIO_PROCESS, process->pid);
    return nice_value;
}

int set_pid_nice(profile_t *process, int priority)
{
    int ret;
    ret = setpriority(PRIO_PROCESS, process->pid, priority);
    return ret;
}


char *get_ioprio(profile_t *process)
{
    int ioprio = syscall(GETIOPRIO, IOPRIO_WHO_PROCESS, process->pid);
    if (ioprio == -1) 
        return NULL;
    char *ioprio_class[4] = {"none/", "rt/", "be/", "idle/"};
    int nice = get_pid_nice(process);
    int ioprio_class_num = IOPRIO_CLASS(ioprio);
    char *class_name = ioprio_class[ioprio_class_num];
    char *ioprio_str = calloc(IOPRIO_SIZE, sizeof(char));
    int ioprio_nice = (nice + 20) / 5;
    sprintf(ioprio_str, "%d", ioprio_nice);
    size_t classlen = strlen(class_name);
    char *priority = calloc(classlen + IOPRIO_SIZE, sizeof(char));
    strcat(priority, class_name);
    strcat(priority, ioprio_str); 
    return priority;
}

int set_ioprio(profile_t *process, int class, int value)
{
    int ioprio = IOPRIO_VALUE(class, value);
    int setioprio = syscall(SETIOPRIO, IOPRIO_WHO_PROCESS, 
                            process->pid, ioprio);
    if (setioprio == -1) 
        return -1;
    return 0;
}

void max_proc_res(profile_t *process, int resource, int *value)
{
    int ret;
    if (value == NULL) {
        struct rlimit *old_limit = malloc(sizeof *old_limit);        
        struct rlimit *new_limit = NULL;
        ret = prlimit(process->pid, resource, new_limit, old_limit);
        if (ret == -1) {
            process->max_res = (unsigned) errno;
        } else {
            process->max_res = (unsigned) old_limit->rlim_max;
        } 
    } else {
        struct rlimit *new_limit = malloc(sizeof *new_limit);
        struct rlimit *old_limit = NULL;
        new_limit->rlim_max = *value;
        ret = prlimit(process->pid, resource, new_limit, old_limit);
        if (ret == -1) {
            process->max_res = (unsigned) errno;
        } else {
            process->max_res = (unsigned) *value;
        }
    }
}

void cur_proc_res(profile_t *process, int resource, int *value)
{
    int ret;
    if (value == NULL) {
        struct rlimit *old_limit = malloc(sizeof *old_limit);        
        struct rlimit *new_limit = NULL;
        ret = prlimit(process->pid, resource, new_limit, old_limit);
        if (ret == -1) {
            process->cur_res = (unsigned) errno;
        } else {
            process->cur_res = (unsigned) old_limit->rlim_cur;
        }
    } else {
        struct rlimit *new_limit = malloc(sizeof *new_limit);
        struct rlimit *old_limit = NULL;
        new_limit->rlim_cur = *value;
        ret = prlimit(process->pid, resource, new_limit, old_limit);
        if (ret == -1) {
            process->cur_res = (unsigned) errno;
        } else {
            process->cur_res = (unsigned) *value;
        }
    }
}
