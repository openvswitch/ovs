/* Utility functions for hooking process termination signals.
 *
 * Hooks registered with this module are called by handlers for signals that
 * terminate the process normally (e.g. SIGTERM, SIGINT).  They are not called
 * for signals that indicate program errors (e.g. SIGFPE, SIGSEGV).  They are
 * useful for cleanup, such as deleting temporary files.
 *
 * The hooks are not called upon normal process termination via exit().  Use
 * atexit() to hook normal process termination.
 *
 * These functions will only work properly for single-threaded processes. */

#ifndef FATAL_SIGNAL_H
#define FATAL_SIGNAL_H 1

/* Basic interface. */
void fatal_signal_add_hook(void (*)(void *aux), void *aux);
void fatal_signal_block(void);
void fatal_signal_unblock(void);

/* Convenience functions for unlinking files upon termination.
 *
 * These functions also unlink the files upon normal process termination via
 * exit(). */
void fatal_signal_add_file_to_unlink(const char *);
void fatal_signal_remove_file_to_unlink(const char *);

#endif /* fatal-signal.h */
