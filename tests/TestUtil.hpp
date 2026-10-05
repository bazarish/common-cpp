// Bazarish project (c) 2026
#pragma once

#include <cstdio>
#include <cstdlib>

#define CHECK(condition)                                                            \
    do {                                                                            \
        if (!(condition)) {                                                         \
            std::fprintf(stderr, "CHECK failed at %s:%d: %s\n", __FILE__, __LINE__, \
                #condition);                                                        \
            std::exit(1);                                                           \
        }                                                                           \
    } while (false)

#define CHECK_THROWS(expression)                                                        \
    do {                                                                                \
        bool thrown = false;                                                            \
        try {                                                                           \
            (void)(expression);                                                         \
        } catch (const std::exception&) {                                               \
            thrown = true;                                                              \
        }                                                                               \
        if (!thrown) {                                                                  \
            std::fprintf(stderr, "CHECK_THROWS failed at %s:%d: %s did not throw\n",    \
                __FILE__, __LINE__, #expression);                                       \
            std::exit(1);                                                               \
        }                                                                               \
    } while (false)
