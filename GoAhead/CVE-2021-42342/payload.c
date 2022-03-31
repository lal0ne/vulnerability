#include <unistd.h>

static void before_main(void) __attribute__((constructor));

static void before_main(void)
{
    write(1, "Hello: World\r\n\r\n", 16);
    write(1, "Hacked\n", 7);
}
