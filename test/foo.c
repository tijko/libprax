#include <stdio.h>
#include <prax.h>


int main(int argc, char *argv[])
{
    profile_t p = init_profile();
    p.pidstr = "637";
    pid_name(&p);
    if (p.name) {
        printf("Name: %s\n", p.name);
        process_fd_stats(&p);
        printf("%d %d %d\n", p.fd->file_stats.st_uid,
                             p.fd->file_stats.st_mode,
                             (int) p.fd->file_stats.st_size);
    } 

        
    return 0;
}
