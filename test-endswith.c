#include <stdio.h>
#include "string_common.h"

int main() {
    int result1, result2;
    char *foo = "this is a string";
    char *bar = "string";

    printf("endswith(\"%s\", \"%s\") = %d\n",
	   foo,
	   bar,
	   result1 = endswith(foo, bar));
    printf("endswith(\"string\", \"asdf\") = %d\n",
	   result2 = endswith("string", "asdf"));

    return (result1 == 1) && (result2 == 0) ? 0 : 1;
}
