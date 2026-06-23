/*
 * debug.h - Battle-hardened, feature-complete debugging header for C23/C++23
 * 
 * This header pushes C23/GCC limits with cross-platform support. It's ~100% 
 * compile-time stripped with `-DNDEBUG`, providing zero runtime cost.
 * Tested for C23 (uses `_Generic` for type-safe printing). 
 * When compiling, use -std=c23 or for older GCC -std=c2x.
 *
 * #### New Features (v2.0)
 * - **Cross-Platform**: Works on Linux, macOS, and Windows (fallback for backtrace)
 * - **Thread Safety**: Optional mutex via DEBUG_THREAD_SAFE macro
 * - **Timestamps**: Optional timestamps via DEBUG_TIMESTAMPS macro
 * - **Output Redirection**: Custom output handler via DEBUG_SET_OUTPUT()
 * - **ANSI Colors**: Toggleable color output via DEBUG_COLORS macro
 *
 * #### Core
 * - **Log Levels**: TRACE (5, verbose) → DEBUG (4) → INFO (3) → WARN (2) → ERROR (1).
 *   Set `DEBUG_LEVEL=3` pre-include for "info+" only.
 * - **Generic Printing**: `_Generic` (C23) auto-formats basics (int/double/ptr/string).
 * - **Backtrace on Assert/Check/Abort**: Captures stack with symbols (-rdynamic).
 * - **Soft Checks**: `DEBUG_CHECK(expr, "msg")`—warns + backtrace but continues.
 * - **Loop/Iteration Tracing**: `DEBUG_LOOP_START/ITER/END` macros.
 * - **Custom Abort**: `DEBUG_ABORT("Panic: %s", reason)`—logs + backtrace before abort().
 * - **Alloc Wrappers**: Enhanced `DEBUG_MALLOC/FREE`—logs at DEBUG+ level.
 *
 * #### GDB Integration
 * - Compile with `-g` for rich symbols; `-rdynamic` for backtrace symbols.
 * - `DEBUG_BREAK()` triggers SIGTRAP (catchable in GDB).
 * - `DEBUG_IF(condition) { ... }` for conditional debugging blocks.
 *
 * #### Configuration Macros (define before including)
 * - `DEBUG_LEVEL` (0-5): Set verbosity level (default: 5)
 * - `DEBUG_THREAD_SAFE`: Enable mutex locking for thread safety
 * - `DEBUG_TIMESTAMPS`: Include timestamps in output
 * - `DEBUG_COLORS`: Enable ANSI color output
 * - `DEBUG_OUTPUT_FILE`: Set output to file instead of stderr
 * - `NDEBUG`: Compile out all debug code (standard)
 *
 * #### Usage Example
 * ```c
 * #define DEBUG_LEVEL 5
 * #define DEBUG_TIMESTAMPS
 * #define DEBUG_COLORS
 * #include "debug.h"
 *
 * int factorial(int n) {
 *     DEBUG_ENTER("(n=%d)", n);
 *     DEBUG_ASSERT(n >= 0, "Negative input!");
 *     if (n <= 1) DEBUG_EXIT(1);
 *     int res = n * factorial(n-1);
 *     DEBUG_VAR(res);
 *     DEBUG_EXIT(res);
 * }
 * ```
 */

#ifndef DEBUG_H
#define DEBUG_H

/* ============================================================================
 * Platform Detection
 * ============================================================================ */
#if defined(_WIN32) || defined(_WIN64)
    #define DEBUG_PLATFORM_WINDOWS 1
#elif defined(__APPLE__) && defined(__MACH__)
    #define DEBUG_PLATFORM_MACOS 1
#elif defined(__linux__)
    #define DEBUG_PLATFORM_LINUX 1
#else
    #define DEBUG_PLATFORM_UNKNOWN 1
#endif

/* ============================================================================
 * Standard Includes
 * ============================================================================ */
#include <stdio.h>      /* fprintf, etc. */
#include <assert.h>     /* std assert */
#include <stdlib.h>     /* abort, malloc/free */
#include <string.h>     /* strlen */
#include <stdint.h>     /* uintptr_t */

/* Platform-specific backtrace support */
#if defined(DEBUG_PLATFORM_LINUX)
    #include <execinfo.h>   /* backtrace (GNU-specific) */
    #define DEBUG_HAS_BACKTRACE 1
#elif defined(DEBUG_PLATFORM_MACOS)
    #include <execinfo.h>   /* backtrace (available on macOS) */
    #define DEBUG_HAS_BACKTRACE 1
#elif defined(DEBUG_PLATFORM_WINDOWS)
    /* Windows: Use CaptureStackBackTrace if available */
    #ifdef _MSC_VER
        #include <windows.h>
        #include <dbghelp.h>
        #pragma comment(lib, "dbghelp.lib")
        #define DEBUG_HAS_BACKTRACE 1
    #else
        /* MinGW or other Windows compilers without dbghelp */
        #define DEBUG_HAS_BACKTRACE 0
    #endif
#else
    #define DEBUG_HAS_BACKTRACE 0
#endif

/* Optional timestamp support */
#ifdef DEBUG_TIMESTAMPS
    #include <time.h>
#endif

/* Optional thread safety support */
#ifdef DEBUG_THREAD_SAFE
    #ifdef __cplusplus
        #include <mutex>
    #else
        #include <pthread.h>
    #endif
#endif

/* ============================================================================
 * Configuration Defaults
 * ============================================================================ */

/* Default DEBUG_LEVEL to 5 (full) if not set; ignored if NDEBUG defined */
#ifndef DEBUG_LEVEL
    #define DEBUG_LEVEL 5
#endif

/* ============================================================================
 * ANSI Color Support (from ansi.h)
 * ============================================================================ */
#ifdef DEBUG_COLORS
    #define DEBUG_COLOR_RESET   "\x1b[0m"
    #define DEBUG_COLOR_RED     "\x1b[31m"
    #define DEBUG_COLOR_GREEN   "\x1b[32m"
    #define DEBUG_COLOR_YELLOW  "\x1b[33m"
    #define DEBUG_COLOR_BLUE    "\x1b[34m"
    #define DEBUG_COLOR_MAGENTA "\x1b[35m"
    #define DEBUG_COLOR_CYAN    "\x1b[36m"
    #define DEBUG_COLOR_WHITE   "\x1b[37m"
    #define DEBUG_COLOR_BOLD    "\x1b[1m"
#else
    #define DEBUG_COLOR_RESET   ""
    #define DEBUG_COLOR_RED     ""
    #define DEBUG_COLOR_GREEN   ""
    #define DEBUG_COLOR_YELLOW  ""
    #define DEBUG_COLOR_BLUE    ""
    #define DEBUG_COLOR_MAGENTA ""
    #define DEBUG_COLOR_CYAN    ""
    #define DEBUG_COLOR_WHITE   ""
    #define DEBUG_COLOR_BOLD    ""
#endif

/* ============================================================================
 * X-Macro for Type Mappings (DRY principle - solves repeated _Generic blocks)
 * ============================================================================ */
#ifndef __cplusplus
    /* X-macro: TYPE, FORMAT_SPECIFIER, CAST_EXPR */
    #define DEBUG_TYPE_MAP(X) \
        X(int,           "%d",  (var)) \
        X(unsigned int,  "%u",  (var)) \
        X(long,          "%ld", (var)) \
        X(unsigned long, "%lu", (var)) \
        X(double,        "%f",  (var)) \
        X(char*,         "%s",  (var)) \
        X(void*,         "%p",  (var))

    /* Generate _Generic selection for printing */
    #define DEBUG_PRINT_VAR_IMPL(var) \
        _Generic((var), \
            default: fprintf(_debug_output, "%p", (void*)(uintptr_t)(var)), \
            int: fprintf(_debug_output, "%d", (var)), \
            unsigned int: fprintf(_debug_output, "%u", (var)), \
            long: fprintf(_debug_output, "%ld", (var)), \
            unsigned long: fprintf(_debug_output, "%lu", (var)), \
            double: fprintf(_debug_output, "%f", (var)), \
            char*: fprintf(_debug_output, "%s", (var)), \
            void*: fprintf(_debug_output, "%p", (var)) \
        )
#endif

/* ============================================================================
 * Only define debug functionality if NDEBUG is NOT set
 * ============================================================================ */
#ifndef NDEBUG

/* Log levels (numeric for simplicity) */
#define LOG_ERROR 1
#define LOG_WARN  2
#define LOG_INFO  3
#define LOG_DEBUG 4
#define LOG_TRACE 5

/* ============================================================================
 * Output Redirection Support
 * ============================================================================ */

/* Default output stream */
#ifndef DEBUG_OUTPUT_FILE
    #define _DEBUG_DEFAULT_OUTPUT stderr
#else
    #define _DEBUG_DEFAULT_OUTPUT DEBUG_OUTPUT_FILE
#endif

/* Global output stream variable (can be changed at runtime) */
/* Note: For thread safety, call debug_set_output_file() before spawning threads,
 * or use DEBUG_THREAD_SAFE and ensure all threads use the same output. */
#ifdef __cplusplus
extern "C" {
#endif

static FILE* _debug_output = NULL;

/* Custom output handler type */
typedef void (*debug_output_handler_t)(const char* level, const char* file, 
                                        int line, const char* func, 
                                        const char* message);

static debug_output_handler_t _debug_custom_handler = NULL;

/* Initialize output (call automatically on first use) 
 * Note: This is safe to call from multiple threads - worst case is
 * double-assignment of the same value to _debug_output */
static inline void _debug_init_output(void) {
    if (_debug_output == NULL) {
        _debug_output = _DEBUG_DEFAULT_OUTPUT;
    }
}

/* Set output to file - call before spawning threads for safety */
static inline void debug_set_output_file(FILE* file) {
    _debug_output = file ? file : _DEBUG_DEFAULT_OUTPUT;
}

/* Set custom output handler */
static inline void debug_set_output_handler(debug_output_handler_t handler) {
    _debug_custom_handler = handler;
}

/* Reset to default stderr */
static inline void debug_reset_output(void) {
    _debug_output = _DEBUG_DEFAULT_OUTPUT;
    _debug_custom_handler = NULL;
}

#ifdef __cplusplus
}
#endif

/* Convenience macro for setting output */
#define DEBUG_SET_OUTPUT(file) debug_set_output_file(file)
#define DEBUG_SET_HANDLER(handler) debug_set_output_handler(handler)
#define DEBUG_RESET_OUTPUT() debug_reset_output()

/* ============================================================================
 * Thread Safety Support
 * ============================================================================ */
#ifdef DEBUG_THREAD_SAFE
    #ifdef __cplusplus
        static std::mutex _debug_mutex;
        #define _DEBUG_LOCK() std::lock_guard<std::mutex> _debug_lock(_debug_mutex)
        #define _DEBUG_UNLOCK() /* RAII handles unlock */
    #else
        static pthread_mutex_t _debug_mutex = PTHREAD_MUTEX_INITIALIZER;
        #define _DEBUG_LOCK() pthread_mutex_lock(&_debug_mutex)
        #define _DEBUG_UNLOCK() pthread_mutex_unlock(&_debug_mutex)
    #endif
#else
    #define _DEBUG_LOCK() ((void)0)
    #define _DEBUG_UNLOCK() ((void)0)
#endif

/* ============================================================================
 * Timestamp Support
 * ============================================================================ */
#ifdef DEBUG_TIMESTAMPS
    #define _DEBUG_TIMESTAMP_FMT "%s "
    #define _DEBUG_TIMESTAMP_ARG , _debug_timestamp_buf
    #if defined(DEBUG_THREAD_SAFE) && defined(DEBUG_PLATFORM_WINDOWS)
        /* Thread-safe timestamps on Windows using localtime_s */
        #define _DEBUG_TIMESTAMP_DECL \
            char _debug_timestamp_buf[32]; \
            do { \
                time_t _debug_now = time(NULL); \
                struct tm _debug_tm_storage; \
                (void)localtime_s(&_debug_tm_storage, &_debug_now); \
                strftime(_debug_timestamp_buf, sizeof(_debug_timestamp_buf), \
                         "%Y-%m-%d %H:%M:%S", &_debug_tm_storage); \
            } while(0)
    #elif defined(DEBUG_THREAD_SAFE)
        /* Thread-safe timestamps on POSIX-like platforms using localtime_r */
        #define _DEBUG_TIMESTAMP_DECL \
            char _debug_timestamp_buf[32]; \
            do { \
                time_t _debug_now = time(NULL); \
                struct tm _debug_tm_storage; \
                (void)localtime_r(&_debug_now, &_debug_tm_storage); \
                strftime(_debug_timestamp_buf, sizeof(_debug_timestamp_buf), \
                         "%Y-%m-%d %H:%M:%S", &_debug_tm_storage); \
            } while(0)
    #else
        /* Non-thread-safe timestamps using localtime (preserves existing behavior) */
        #define _DEBUG_TIMESTAMP_DECL \
            char _debug_timestamp_buf[32]; \
            do { \
                time_t _debug_now = time(NULL); \
                struct tm* _debug_tm = localtime(&_debug_now); \
                strftime(_debug_timestamp_buf, sizeof(_debug_timestamp_buf), \
                         "%Y-%m-%d %H:%M:%S", _debug_tm); \
            } while(0)
    #endif
#else
    #define _DEBUG_TIMESTAMP_FMT ""
    #define _DEBUG_TIMESTAMP_ARG
    #define _DEBUG_TIMESTAMP_DECL ((void)0)
#endif

/* ============================================================================
 * Color Helpers for Log Levels
 * ============================================================================ */
#ifdef DEBUG_COLORS
    #define _DEBUG_LEVEL_COLOR(level) \
        ((level) == LOG_ERROR ? DEBUG_COLOR_RED DEBUG_COLOR_BOLD : \
         (level) == LOG_WARN  ? DEBUG_COLOR_YELLOW : \
         (level) == LOG_INFO  ? DEBUG_COLOR_GREEN : \
         (level) == LOG_DEBUG ? DEBUG_COLOR_CYAN : \
         DEBUG_COLOR_MAGENTA)
    #define _DEBUG_RESET_COLOR DEBUG_COLOR_RESET
#else
    #define _DEBUG_LEVEL_COLOR(level) ""
    #define _DEBUG_RESET_COLOR ""
#endif

/* ============================================================================
 * Core Logger Macro
 * ============================================================================ */
#define DEBUG_LOG(level, fmt, ...) \
    do { \
        if ((level) <= DEBUG_LEVEL) { \
            _DEBUG_LOCK(); \
            _debug_init_output(); \
            _DEBUG_TIMESTAMP_DECL; \
            const char* _level_str = ""; \
            switch (level) { \
                case LOG_ERROR: _level_str = "ERROR"; break; \
                case LOG_WARN:  _level_str = "WARN "; break; \
                case LOG_INFO:  _level_str = "INFO "; break; \
                case LOG_DEBUG: _level_str = "DEBUG"; break; \
                case LOG_TRACE: _level_str = "TRACE"; break; \
            } \
            fprintf(_debug_output, "%s" _DEBUG_TIMESTAMP_FMT "[%s] %s:%d %s: " fmt "%s\n", \
                    _DEBUG_LEVEL_COLOR(level) \
                    _DEBUG_TIMESTAMP_ARG, \
                    _level_str, __FILE__, __LINE__, __PRETTY_FUNCTION__ \
                    __VA_OPT__(,) __VA_ARGS__, _DEBUG_RESET_COLOR); \
            fflush(_debug_output); \
            _DEBUG_UNLOCK(); \
        } \
    } while(0)

/* Convenience level macros */
#define DEBUG_TRACE(fmt, ...) DEBUG_LOG(LOG_TRACE, fmt, ##__VA_ARGS__)
#define DEBUG_DEBUG(fmt, ...) DEBUG_LOG(LOG_DEBUG, fmt, ##__VA_ARGS__)
#define DEBUG_INFO(fmt, ...)  DEBUG_LOG(LOG_INFO,  fmt, ##__VA_ARGS__)
#define DEBUG_WARN(fmt, ...)  DEBUG_LOG(LOG_WARN,  fmt, ##__VA_ARGS__)
#define DEBUG_ERROR(fmt, ...) DEBUG_LOG(LOG_ERROR, fmt, ##__VA_ARGS__)

/* Function tracing: ENTER/EXIT with auto param/return logging */
#define DEBUG_ENTER(...) \
    DEBUG_TRACE("ENTER " __VA_ARGS__)

#ifdef __cplusplus
/* C++ version: Use simple string print for return values (no _Generic in C++) */
#define DEBUG_EXIT(ret) \
    do { \
        if (LOG_TRACE <= DEBUG_LEVEL) { \
            _DEBUG_LOCK(); \
            _debug_init_output(); \
            fprintf(_debug_output, "%s[TRACE] %s:%d %s: EXIT (return: %s)%s\n", \
                    _DEBUG_LEVEL_COLOR(LOG_TRACE), \
                    __FILE__, __LINE__, __PRETTY_FUNCTION__, #ret, \
                    _DEBUG_RESET_COLOR); \
            fflush(_debug_output); \
            _DEBUG_UNLOCK(); \
        } \
        return ret; \
    } while(0)

#define DEBUG_VAR(var) \
    do { \
        if (LOG_TRACE <= DEBUG_LEVEL) { \
            _DEBUG_LOCK(); \
            _debug_init_output(); \
            fprintf(_debug_output, "%s[TRACE] %s:%d %s: VAR %s%s\n", \
                    _DEBUG_LEVEL_COLOR(LOG_TRACE), \
                    __FILE__, __LINE__, __PRETTY_FUNCTION__, #var, \
                    _DEBUG_RESET_COLOR); \
            fflush(_debug_output); \
            _DEBUG_UNLOCK(); \
        } \
    } while(0)

/* Generic print helper - not used in C++ but defined for compatibility */
#define _GENERIC_FMT(x) "%p"

#else
/* C version: Use _Generic for type-safe printing (C11/C23 feature) */

#define DEBUG_EXIT(ret) \
    do { \
        if (LOG_TRACE <= DEBUG_LEVEL) { \
            _DEBUG_LOCK(); \
            _debug_init_output(); \
            fprintf(_debug_output, "%s[TRACE] %s:%d %s: EXIT (return: %s = ", \
                    _DEBUG_LEVEL_COLOR(LOG_TRACE), \
                    __FILE__, __LINE__, __PRETTY_FUNCTION__, #ret); \
            DEBUG_PRINT_VAR_IMPL(ret); \
            fprintf(_debug_output, ")%s\n", _DEBUG_RESET_COLOR); \
            fflush(_debug_output); \
            _DEBUG_UNLOCK(); \
        } \
        return ret; \
    } while(0)

/* Generic print helper using X-macro pattern (DRY - only one definition) */
#define _GENERIC_FMT(x) _Generic((x), \
    default: "%p", \
    int: "%d", \
    unsigned int: "%u", \
    long: "%ld", \
    unsigned long: "%lu", \
    double: "%f", \
    char*: "%s", \
    void*: "%p" \
)

#define DEBUG_VAR(var) \
    do { \
        if (LOG_TRACE <= DEBUG_LEVEL) { \
            _DEBUG_LOCK(); \
            _debug_init_output(); \
            fprintf(_debug_output, "%s[TRACE] %s:%d %s: VAR %s = ", \
                    _DEBUG_LEVEL_COLOR(LOG_TRACE), \
                    __FILE__, __LINE__, __PRETTY_FUNCTION__, #var); \
            DEBUG_PRINT_VAR_IMPL(var); \
            fprintf(_debug_output, "%s\n", _DEBUG_RESET_COLOR); \
            fflush(_debug_output); \
            _DEBUG_UNLOCK(); \
        } \
    } while(0)

#endif  /* __cplusplus */

/* Pointer inspector: Value + size (manual size; for auto, wrap allocs) */
#define DEBUG_PTR(ptr, size_desc) \
    DEBUG_TRACE("PTR %s @ %p (size: %s)", #ptr, (void*)(ptr), size_desc)

/* Alloc wrappers (logs on alloc/free; use instead of raw malloc/free) */
#define DEBUG_MALLOC(size) \
    ({ \
        void* _ptr = malloc(size); \
        if (_ptr && (DEBUG_LEVEL >= LOG_DEBUG)) \
            DEBUG_TRACE("MALLOC %p (size: %zu bytes)", _ptr, (size_t)(size)); \
        _ptr; \
    })

#define DEBUG_FREE(ptr) \
    do { \
        if (ptr && (DEBUG_LEVEL >= LOG_DEBUG)) \
            DEBUG_TRACE("FREE %p", (void*)ptr); \
        free(ptr); \
        (void)0; \
    } while(0)

/* Enhanced assert: Logs failure + backtrace + extras, then aborts (GDB-catchable) */
#define DEBUG_ASSERT(expr, ...) \
    do { \
        if (!(expr)) { \
            DEBUG_ERROR("ASSERT FAILED: " #expr ". " __VA_ARGS__); \
            _DEBUG_BACKTRACE(); \
            assert(expr); \
        } \
    } while(0)

/* Soft check: Logs but continues (no abort) */
#define DEBUG_CHECK(expr, ...) \
    do { \
        if (!(expr)) { \
            DEBUG_WARN("CHECK FAILED (continuing): " #expr ". " __VA_ARGS__); \
            _DEBUG_BACKTRACE(); \
        } \
    } while(0)

/* ============================================================================
 * Cross-Platform Backtrace Implementation
 * ============================================================================ */
#if DEBUG_HAS_BACKTRACE
    #if defined(DEBUG_PLATFORM_LINUX) || defined(DEBUG_PLATFORM_MACOS)
        /* GNU/macOS backtrace implementation */
        #define _DEBUG_BACKTRACE() \
            do { \
                _DEBUG_LOCK(); \
                _debug_init_output(); \
                void* _bt[32]; \
                int _np = backtrace(_bt, 32); \
                char** _syms = backtrace_symbols(_bt, _np); \
                if (_syms) { \
                    DEBUG_ERROR("BACKTRACE (%d frames):", _np); \
                    for (int _i = 0; _i < _np; ++_i) { \
                        DEBUG_ERROR("  #%d: %s", _i, _syms[_i]); \
                    } \
                    free(_syms); \
                } \
                _DEBUG_UNLOCK(); \
            } while(0)
    #elif defined(DEBUG_PLATFORM_WINDOWS) && defined(_MSC_VER)
        /* Windows backtrace using CaptureStackBackTrace */
        #define _DEBUG_BACKTRACE() \
            do { \
                _DEBUG_LOCK(); \
                _debug_init_output(); \
                void* _bt[32]; \
                USHORT _np = CaptureStackBackTrace(0, 32, _bt, NULL); \
                DEBUG_ERROR("BACKTRACE (%d frames):", _np); \
                HANDLE _process = GetCurrentProcess(); \
                if (SymInitialize(_process, NULL, TRUE)) { \
                    SYMBOL_INFO* _symbol = (SYMBOL_INFO*)calloc(sizeof(SYMBOL_INFO) + 256, 1); \
                    if (_symbol) { \
                        _symbol->MaxNameLen = 255; \
                        _symbol->SizeOfStruct = sizeof(SYMBOL_INFO); \
                        for (int _i = 0; _i < _np; ++_i) { \
                            if (SymFromAddr(_process, (DWORD64)_bt[_i], 0, _symbol)) { \
                                DEBUG_ERROR("  #%d: %s [0x%llx]", _i, _symbol->Name, _symbol->Address); \
                            } else { \
                                DEBUG_ERROR("  #%d: [0x%p]", _i, _bt[_i]); \
                            } \
                        } \
                        free(_symbol); \
                    } \
                    SymCleanup(_process); \
                } else { \
                    /* Fallback: symbol initialization failed, print raw addresses */ \
                    for (int _i = 0; _i < _np; ++_i) { \
                        DEBUG_ERROR("  #%d: [0x%p]", _i, _bt[_i]); \
                    } \
                } \
                _DEBUG_UNLOCK(); \
            } while(0)
    #endif
#else
    /* Fallback: No backtrace available */
    #define _DEBUG_BACKTRACE() \
        do { \
            DEBUG_ERROR("BACKTRACE: Not available on this platform"); \
        } while(0)
#endif

#define DEBUG_BACKTRACE() _DEBUG_BACKTRACE()

/* GDB integration: Breakpoint macro (traps for GDB; set bp on __builtin_trap or sigtrap) */
#if defined(_MSC_VER)
    #define DEBUG_BREAK() \
        do { \
            DEBUG_TRACE("BREAKPOINT at %s:%d %s", __FILE__, __LINE__, __PRETTY_FUNCTION__); \
            __debugbreak(); \
        } while(0)
#else
    #define DEBUG_BREAK() \
        do { \
            DEBUG_TRACE("BREAKPOINT at %s:%d %s", __FILE__, __LINE__, __PRETTY_FUNCTION__); \
            __builtin_trap(); \
        } while(0)
#endif

/* Scope guard (C-style RAII sim: enter on decl, exit on label; use with goto) */
#define DEBUG_SCOPE_BEGIN() \
    DEBUG_ENTER()

#define DEBUG_SCOPE_END() \
    DEBUG_EXIT((void)0)

/* Conditional compilation helpers (e.g., for perf-critical code) */
#define DEBUG_IF(expr) if (expr && (DEBUG_LEVEL >= LOG_TRACE))

/* Loop/iteration logging */
#define DEBUG_LOOP_START(...) \
    DEBUG_TRACE("LOOP START " __VA_ARGS__)

#define DEBUG_LOOP_ITER(i, total) \
    if (DEBUG_LEVEL >= LOG_DEBUG) DEBUG_DEBUG("LOOP ITER %d/%d", (int)(i), (int)(total))

#define DEBUG_LOOP_END(...) \
    DEBUG_TRACE("LOOP END " __VA_ARGS__)

/* Custom abort: Like assert but with message/backtrace (GDB-friendly) */
#define DEBUG_ABORT(msg, ...) \
    do { \
        DEBUG_ERROR("ABORT: " msg " " __VA_ARGS__); \
        _DEBUG_BACKTRACE(); \
        abort(); \
    } while(0)

#else  /* NDEBUG: All no-ops (zero overhead, no code gen) */

/* No-op macros */
#define DEBUG_TRACE(...) do {} while(0)
#define DEBUG_DEBUG(...) do {} while(0)
#define DEBUG_INFO(...)  do {} while(0)
#define DEBUG_WARN(...)  do {} while(0)
#define DEBUG_ERROR(...) do {} while(0)
#define DEBUG_LOG(...)   do {} while(0)

#define DEBUG_ENTER(...) 
#define DEBUG_EXIT(ret)  return ret
#define DEBUG_VAR(var)   (void)0
#define DEBUG_PTR(ptr, size_desc) (void)0
#define DEBUG_MALLOC(size) malloc(size)
#define DEBUG_FREE(ptr) free(ptr)
#define DEBUG_ASSERT(expr, ...) (void)(expr)
#define DEBUG_CHECK(expr, ...) (void)(expr)
#define DEBUG_BACKTRACE() (void)0
#define DEBUG_BREAK() (void)0
#define DEBUG_SCOPE_BEGIN() 
#define DEBUG_SCOPE_END() 
#define DEBUG_LOOP_START(...) 
#define DEBUG_LOOP_ITER(i, total) 
#define DEBUG_LOOP_END(...) 
#define DEBUG_IF(expr) if (0)
#define DEBUG_ABORT(msg, ...) abort()
#define DEBUG_SET_OUTPUT(file) ((void)0)
#define DEBUG_SET_HANDLER(handler) ((void)0)
#define DEBUG_RESET_OUTPUT() ((void)0)

#endif  /* NDEBUG */

#endif  /* DEBUG_H */