#include <unistd.h>
#include <fcntl.h>

#include <sys/types.h>

int main(int argc, char **argv, char **envp)
{
    const char *args[] = {"/bin/bash", "-i", NULL};

    setuid(0);
    setgid(0);
    execve(args[0], (char **)args, envp);
}
