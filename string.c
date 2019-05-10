#include <stdbool.h>

bool startswith(const char *string, const char *prefix) {
    while (*prefix)
        if (*prefix++ != *string++)
            return false;
    return true;
}

