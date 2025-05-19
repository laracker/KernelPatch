#define RANDOM_CHARS "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
#define RANDOM_CHARS_LEN (sizeof(RANDOM_CHARS) - 1)
#define MAX_FILTER_KEYWORDS 5

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))
#endif

struct seq_file {
    char *buf;
    size_t size;
    size_t from;
    size_t count;
    //...
};

struct hook_funcs {
    void *original;
    void *replacement;
    void **backup;
};

struct filter_keyword {
    const char *keyword;
    size_t len;
};

#include <hook.h> // Add this line to use hook_err_t and its members from hook.h

