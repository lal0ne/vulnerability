#ifndef _HELPER_H_
#define _HELPER_H_

#include <unistd.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <fcntl.h>

typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

typedef void* kaddr_t;

#define U8_MAX		((u8)~0U)
#define S8_MAX		((s8)(U8_MAX >> 1))
#define S8_MIN		((s8)(-S8_MAX - 1))
#define U16_MAX		((u16)~0U)
#define S16_MAX		((s16)(U16_MAX >> 1))
#define S16_MIN		((s16)(-S16_MAX - 1))
#define U32_MAX		((u32)~0U)
#define S32_MAX		((s32)(U32_MAX >> 1))
#define S32_MIN		((s32)(-S32_MAX - 1))
#define U64_MAX		((u64)~0ULL)
#define S64_MAX		((s64)(U64_MAX >> 1))
#define S64_MIN		((s64)(-S64_MAX - 1))

int urandom()
{
    int r;
    int rand_fd = open("/dev/urandom", O_RDONLY);
    if (rand_fd < 0) {
        return r;
    }
    read(rand_fd, &r, sizeof(r));
    close(rand_fd);
    return r;
}

void *memmem(const void *haystack, size_t haystack_len,
                const void *needle, size_t needle_len)
{
	const char *begin = haystack;
	const char *last_possible = begin + haystack_len - needle_len;
	const char *tail = needle;
	char point;

	/*
	 * The first occurrence of the empty string is deemed to occur at
	 * the beginning of the string.
	 */
	if (needle_len == 0)
		return (void *)begin;

	/*
	 * Sanity check, otherwise the loop might search through the whole
	 * memory.
	 */
	if (haystack_len < needle_len)
		return NULL;

	point = *tail++;
	for (; begin <= last_possible; begin++) {
		if (*begin == point && !memcmp(begin + 1, tail, needle_len - 1))
			return (void *)begin;
	}

	return NULL;
}

int memoff(const void *haystack, size_t haystack_len,
                const void *needle, size_t needle_len)
{
    void *found = memmem(haystack, haystack_len, needle, needle_len);
    if (found) {
        return (int)(found - haystack);
    }
    return -1;
}

#endif /* _HELPER_H_ */