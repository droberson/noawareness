/* string.c - various string-related functions that don't come with string.h */

#include <string.h>
#include <stdbool.h>

/* startswith() - Check if string starts with prefix.
 *
 * Args:
 *     string - String to check (haystack).
 *     prefix - Prefix to check (needle).
 *
 * Returns:
 *     true if 'string' starts with 'prefix', otherwise false.
 */
bool startswith(const char *string, const char *prefix) {
  while (*prefix)
    if (*prefix++ != *string++)
      return false;
  return true;
}

/* endswith() - Check if string ends with suffix.
 *
 * Args:
 *     string - String to check (haystack).
 *     suffix - Suffix to check (needle).
 *
 * Returns:
 *     true if 'string' ends with 'suffix', otherwise false.
 */
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
