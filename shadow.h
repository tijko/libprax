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
    fdstats_t *root;
};

// Check if process exists.
int is_alive(profile_t *process);

// Count digit places in type int of the process being profiled.
int pid_digit_places(int pid);

// Function returns the niceness of the pid being profiled.
int get_pid_nice(profile_t *process);

// Sets the niceness of pid.
int set_pid_nice(profile_t *process, int priority);

#define PROC "/proc/"
#define PROCLEN 6

// Constructs the path from the pid and specific dir being looked up.
char *construct_path(int pid, char *dir);

#define COMM "/comm"

#define FD "/fd/"

// Function to return the name of a pid.
char *pid_name(profile_t *process);

// A function that traverses the "fd" directory of the pid from process
// and loads a fdstat_t struct with stats for each file-descriptor found.
int process_fd_stats(profile_t **process);

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
char *get_ioprio(profile_t *process);
// Sets the I/O scheduling class and priority of profiled pid.
int set_ioprio(profile_t *process, int class, int value);

// sets/gets process resource limits.
unsigned int max_proc_res(profile_t *process, int resource, int new, int old);

unsigned int cur_proc_res(profile_t *process, int resource, int new, int old);
