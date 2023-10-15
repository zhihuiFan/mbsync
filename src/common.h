/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006,2010-2012 Oswald Buddenhagen <ossi@users.sf.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * As a special exception, mbsync may be linked with the OpenSSL library,
 * despite that library's more restrictive license.
 */

#ifndef COMMON_H
#define COMMON_H

#include <autodefs.h>

#include <sys/types.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>

typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

#define as(ar) (sizeof(ar)/sizeof(ar[0]))

#define stringify__(x) #x
#define stringify(x) stringify__(x)

// From https://stackoverflow.com/a/62984543/3685191
#define deparen(x) esc_(ish_ x)
#define esc_(...) esc__(__VA_ARGS__)
#define esc__(...) van_ ## __VA_ARGS__
#define ish_(...) ish_ __VA_ARGS__
#define van_ish_

#define shifted_bit(in, from, to) \
	((int)(((uint)(in) / (from > to ? from / to : 1) * (to > from ? to / from : 1)) & to))

#if __GNUC__ > 2 || (__GNUC__ == 2 && __GNUC_MINOR__ > 4)
# define ATTR_UNUSED __attribute__((unused))
# define ATTR_NORETURN __attribute__((noreturn))
# define ATTR_PRINTFLIKE(fmt,var) __attribute__((format(printf,fmt,var)))
#else
# define ATTR_UNUSED
# define ATTR_NORETURN
# define ATTR_PRINTFLIKE(fmt,var)
#endif

#if defined(__clang__)
# define DO_PRAGMA__(text) _Pragma(#text)
# define DIAG_PUSH DO_PRAGMA__(clang diagnostic push)
# define DIAG_POP DO_PRAGMA__(clang diagnostic pop)
# define DIAG_DISABLE(text) DO_PRAGMA__(clang diagnostic ignored text)
#elif __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 5)
# define DO_PRAGMA__(text) _Pragma(#text)
# define DIAG_PUSH DO_PRAGMA__(GCC diagnostic push)
# define DIAG_POP DO_PRAGMA__(GCC diagnostic pop)
# define DIAG_DISABLE(text) DO_PRAGMA__(GCC diagnostic ignored text)
#else
# define DIAG_PUSH
# define DIAG_POP
# define DIAG_DISABLE(text)
#endif

#if __GNUC__ >= 7 || defined(__clang__)
# define FALLTHROUGH __attribute__((fallthrough));
#else
# define FALLTHROUGH
#endif

#ifdef __GNUC__
# define INLINE __inline__
#else
# define INLINE
#endif

#define EXE "mbsync"

/* main.c */

#define DEBUG_CRASH     0x01
#define DEBUG_MAILDIR   0x02
#define DEBUG_NET       0x04
#define DEBUG_NET_ALL   0x08
#define DEBUG_SYNC      0x10
#define DEBUG_MAIN      0x20
#define DEBUG_DRV       0x40
#define DEBUG_DRV_ALL   0x80
#define DEBUG_ALL       (0xFF & ~(DEBUG_NET_ALL | DEBUG_DRV_ALL))
#define QUIET           0x100
#define VERYQUIET       0x200
#define PROGRESS        0x400
#define VERBOSE         0x800
#define KEEPJOURNAL     0x1000
#define ZERODELAY       0x2000
#define FORCEASYNC      0x4000

extern int DFlags;
extern int JLimit;
extern int UseFSync;
extern char FieldDelimiter;

extern int Pid;
extern char Hostname[256];
extern const char *Home;

extern uint BufferLimit;

extern int new_total[2], new_done[2];
extern int flags_total[2], flags_done[2];
extern int trash_total[2], trash_done[2];

void stats( void );

/* util.c */

void ATTR_PRINTFLIKE(2, 0) vdebug( int, const char *, va_list va );
void ATTR_PRINTFLIKE(2, 0) vdebugn( int, const char *, va_list va );
void ATTR_PRINTFLIKE(1, 2) info( const char *, ... );
void ATTR_PRINTFLIKE(1, 2) infon( const char *, ... );
void ATTR_PRINTFLIKE(1, 2) progress( const char *, ... );
void ATTR_PRINTFLIKE(1, 2) notice( const char *, ... );
void ATTR_PRINTFLIKE(1, 2) warn( const char *, ... );
void ATTR_PRINTFLIKE(1, 2) error( const char *, ... );
void ATTR_PRINTFLIKE(1, 0) vsys_error( const char *, va_list va );
void ATTR_PRINTFLIKE(1, 2) sys_error( const char *, ... );
void flushn( void );

typedef struct string_list {
	struct string_list *next;
	char string[1];
} string_list_t;

void add_string_list_n( string_list_t **list, const char *str, uint len );
void add_string_list( string_list_t **list, const char *str );
void free_string_list( string_list_t *list );

#ifndef HAVE_MEMRCHR
void *memrchr( const void *s, int c, size_t n );
#endif
#ifndef HAVE_STRNLEN
size_t strnlen( const char *str, size_t maxlen );
#endif

int starts_with( const char *str, int strl, const char *cmp, uint cmpl );
int starts_with_upper( const char *str, int strl, const char *cmp, uint cmpl );
int equals( const char *str, int strl, const char *cmp, uint cmpl );

#ifndef HAVE_TIMEGM
time_t timegm( struct tm *tm );
#endif

void *nfmalloc( size_t sz );
void *nfcalloc( size_t sz );
void *nfrealloc( void *mem, size_t sz );
char *nfstrndup( const char *str, size_t nchars );
char *nfstrdup( const char *str );
int ATTR_PRINTFLIKE(2, 0) nfvasprintf( char **str, const char *fmt, va_list va );
int ATTR_PRINTFLIKE(2, 3) nfasprintf( char **str, const char *fmt, ... );
int ATTR_PRINTFLIKE(3, 4) nfsnprintf( char *buf, int blen, const char *fmt, ... );
void ATTR_NORETURN oob( void );
void ATTR_NORETURN oom( void );

char *expand_strdup( const char *s );

int map_name( const char *arg, char **result, uint reserve, const char *in, const char *out );

#define DEFINE_ARRAY_TYPE(T) \
	typedef struct { \
		T *data; \
		uint size; \
	} T##_array_t; \
	typedef union { \
		T##_array_t array; \
		struct { \
			T *data; \
			uint size; \
			uint alloc; \
		}; \
	} T##_array_alloc_t; \
	static INLINE T *T##_array_append( T##_array_alloc_t *arr ) \
	{ \
		if (arr->size == arr->alloc) { \
			arr->alloc = arr->alloc * 2 + 100; \
			arr->data = nfrealloc( arr->data, arr->alloc * sizeof(T) ); \
		} \
		return &arr->data[arr->size++]; \
	}

#define ARRAY_INIT(arr) \
	do { (arr)->data = NULL; (arr)->size = (arr)->alloc = 0; } while (0)

#define ARRAY_SQUEEZE(arr) \
	do { \
		(arr)->data = nfrealloc( (arr)->data, (arr)->size * sizeof((arr)->data[0]) ); \
	} while (0)

DEFINE_ARRAY_TYPE(uint)
void sort_uint_array( uint_array_t array );
int find_uint_array( const uint_array_t array, uint value );

void arc4_init( void );
uchar arc4_getbyte( void );

uint bucketsForSize( uint size );

typedef struct list_head {
	struct list_head *next, *prev;
} list_head_t;

typedef struct notifier {
	struct notifier *next;
	void (*cb)( int what, void *aux );
	void *aux;
#ifdef HAVE_POLL_H
	uint index;
#else
	int fd;
	short events;
#endif
} notifier_t;

#ifdef HAVE_POLL_H
# include <poll.h>
#else
# define POLLIN 1
# define POLLOUT 4
# define POLLERR 8
#endif

void init_notifier( notifier_t *sn, int fd, void (*cb)( int, void * ), void *aux );
void conf_notifier( notifier_t *sn, short and_events, short or_events );
short notifier_config( notifier_t *sn );
void wipe_notifier( notifier_t *sn );

typedef struct {
	list_head_t links;
	void (*cb)( void *aux );
	void *aux;
	time_t timeout;
} wakeup_t;

void init_wakeup( wakeup_t *tmr, void (*cb)( void * ), void *aux );
void conf_wakeup( wakeup_t *tmr, int timeout );
void wipe_wakeup( wakeup_t *tmr );
static INLINE int ATTR_UNUSED pending_wakeup( wakeup_t *tmr ) { return tmr->links.next != NULL; }

void main_loop( void );

#endif
