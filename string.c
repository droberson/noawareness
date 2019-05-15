#include <string.h>
#include <stdbool.h>

bool startswith(const char *string, const char *prefix) {
  while (*prefix)
    if (*prefix++ != *string++)
      return false;
  return true;
}

bool endswith(const char *string, const char *suffix) {
  size_t string_length;
  size_t suffix_length;

  if ((string == NULL) || (suffix == NULL))
    return false;

  string_length = strlen(string);
  suffix_length = strlen(suffix);

  if (suffix_length > string_length)
    return false;

  return (strncmp(string + string_length - suffix_length,
		  suffix,
		  suffix_length) == 0) ? true : false;
}
