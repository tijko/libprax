#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#ifdef __x86_64__
#define SETIOPRIO 251
#define GETIOPRIO 252
#elif __i386__
#define SETIOPRIO 289
#define GETIOPRIO 290
#endif


#define MAXPID 16
#define IOPRIO_SIZE 3

// Buffer size for readlink calls
#define LINKBUFSIZ 1024

#include <sys/stat.h>
#include <unistd.h>
#include <sys/resource.h>

// Typedef to contain stats of file-descriptors.
typedef struct fdstats fdstats_t;

struct fdstats {
    char *file;
    struct stat *file_stats;
    fdstats_t *next_fd;
};

// Typedef of the process being profiled.
typedef struct profile profile_t;

struct profile {
    int pid;
    int cpu_affinity;
    int nice;
    char *pidstr;
    char *name;
    char *io_nice;
    pid_t sid;
    
    rlim_t addr_space_cur;
    rlim_t addr_space_max;
    rlim_t core_cur;
    rlim_t core_max;
    rlim_t cpu_cur;
    rlim_t cpu_max;
    rlim_t data_cur;
    rlim_t data_max;
    rlim_t fsize_cur;
    rlim_t fsize_max;
    rlim_t locks_cur;
    rlim_t locks_max;
    rlim_t memlock_cur;
    rlim_t memlock_max;
    rlim_t msgqueue_cur;
    rlim_t msgqueue_max;
    rlim_t nice_cur;
    rlim_t nice_max;
    rlim_t nofile_cur;
    rlim_t nofile_max;
    rlim_t nproc_cur;
    rlim_t nproc_max;
    rlim_t rss_cur;
    rlim_t rss_max;
    rlim_t rtprio_cur;
    rlim_t rtprio_max;
    rlim_t rttime_cur;
    rlim_t rttime_max;
    rlim_t sigpending_cur;
    rlim_t sigpending_max;
    rlim_t stack_cur;
    rlim_t stack_max;

    fdstats_t *fd;
};

// Check if process exists.
int is_alive(profile_t *process);

// Count digit places in type int of the process being profiled.
int pid_digit_places(int pid);

// Function returns the niceness of the pid being profiled.
void get_pid_nice(profile_t *process);

// Sets the niceness of pid.
void set_pid_nice(profile_t *process, int priority);

#define PROC "/proc/"
#define PROCLEN 6

// Constructs the path from the pid and specific dir being looked up.
char *construct_path(int pathparts, ...);

#define COMM "/comm"

#define FD "/fd/"

// Function to return the name of a pid.
void pid_name(profile_t *process);

// A function that traverses the "fd" directory of the pid from process
// and loads a fdstat_t struct with stats for each file-descriptor found.
int process_fd_stats(profile_t *process);

//XXX These definitions are from linux/ioprio.h
#define IOPRIO_WHO_PROCESS 1
#define IOPRIO_SHIFT 13

enum {
    IOPRIO_CLASS_NONE,
    IOPRIO_CLASS_RT,
    IOPRIO_CLASS_BE,
    IOPRIO_CLASS_IDLE,
};

#define IOPRIO_PRIO_MASK ((1UL << IOPRIO_SHIFT) - 1)

#define IOPRIO_CLASS(mask) ((mask) >> IOPRIO_SHIFT)
#define IOPRIO_DATA(mask) ((mask) & IOPRIO_PRIO_MASK)
#define IOPRIO_VALUE(class, data) (((class) << IOPRIO_SHIFT) | data)

// Returns the I/O scheduling class and priority of profiled pid.
void get_ioprio(profile_t *process);
// Sets the I/O scheduling class and priority of profiled pid.
void set_ioprio(profile_t *process, int class, int value);

// sets/gets process resource limits.

void rlim_cur(profile_t *process, int resource);

void rlim_max(profile_t *process, int resource);

void set_rlim(profile_t *process, int resource, unsigned long lim);

// gets/sets the current processor affinity in profile_t struct;
void cpu_affinity(profile_t *process);

void setcpu_affinity(profile_t *process, int affinity);

// sets the session id field in profile_t struct
void process_sid(profile_t *process);
