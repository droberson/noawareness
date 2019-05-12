#include <stddef.h>
#include <sys/time.h>


double timestamp() {
    struct timeval  tv;

    if (gettimeofday(&tv, NULL) == -1) {
        return -1;
    }

    return tv.tv_sec + (tv.tv_usec * 0.0000001);
}
