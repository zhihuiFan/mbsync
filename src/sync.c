/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2000-2002 Michael R. Elkins <me@mutt.org>
 * Copyright (C) 2002-2006,2010-2013 Oswald Buddenhagen <ossi@users.sf.net>
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

#include "sync.h"

#include <assert.h>
#include <stdio.h>
#include <limits.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>

#if !defined(_POSIX_SYNCHRONIZED_IO) || _POSIX_SYNCHRONIZED_IO <= 0
# define fdatasync fsync
#endif

#define JOURNAL_VERSION "4"

channel_conf_t global_conf;
channel_conf_t *channels;
group_conf_t *groups;

const char *str_fn[] = { "far side", "near side" }, *str_hl[] = { "push", "pull" };

static void ATTR_PRINTFLIKE(1, 2)
debug( const char *msg, ... )
{
	va_list va;

	va_start( va, msg );
	vdebug( DEBUG_SYNC, msg, va );
	va_end( va );
}

static void ATTR_PRINTFLIKE(1, 2)
debugn( const char *msg, ... )
{
	va_list va;

	va_start( va, msg );
	vdebugn( DEBUG_SYNC, msg, va );
	va_end( va );
}

static void
Fclose( FILE *f, int safe )
{
	if ((safe && (fflush( f ) || (UseFSync && fdatasync( fileno( f ) )))) || fclose( f ) == EOF) {
		sys_error( "Error: cannot close file" );
		exit( 1 );
	}
}

static void ATTR_PRINTFLIKE(2, 0)
vFprintf( FILE *f, const char *msg, va_list va )
{
	int r;

	r = vfprintf( f, msg, va );
	if (r < 0) {
		sys_error( "Error: cannot write file" );
		exit( 1 );
	}
}

static void ATTR_PRINTFLIKE(2, 3)
Fprintf( FILE *f, const char *msg, ... )
{
	va_list va;

	va_start( va, msg );
	vFprintf( f, msg, va );
	va_end( va );
}


/* Keep the mailbox driver flag definitions in sync: */
/* grep for MAILBOX_DRIVER_FLAG */
/* The order is according to alphabetical maildir flag sort */
static const char Flags[] = { 'D', 'F', 'P', 'R', 'S', 'T' };

static uchar
parse_flags( const char *buf )
{
	uint i, d;
	uchar flags;

	for (flags = i = d = 0; i < as(Flags); i++)
		if (buf[d] == Flags[i]) {
			flags |= (1 << i);
			d++;
		}
	return flags;
}

static uint
make_flags( uchar flags, char *buf )
{
	uint i, d;

	for (i = d = 0; i < as(Flags); i++)
		if (flags & (1 << i))
			buf[d++] = Flags[i];
	buf[d] = 0;
	return d;
}

// This is the (mostly) persistent status of the sync record.
// Most of these bits are actually mutually exclusive. It is a
// bitfield to allow for easy testing for multiple states.
#define S_EXPIRE       (1<<0)  // the entry is being expired (near side message removal scheduled)
#define S_EXPIRED      (1<<1)  // the entry is expired (near side message removal confirmed)
#define S_PENDING      (1<<2)  // the entry is new and awaits propagation (possibly a retry)
#define S_DUMMY(fn)    (1<<(3+(fn)))  // f/n message is only a placeholder
#define S_SKIPPED      (1<<5)  // pre-1.4 legacy: the entry was not propagated (message is too big)
#define S_DEAD         (1<<7)  // ephemeral: the entry was killed and should be ignored

// Ephemeral working set.
#define W_NEXPIRE      (1<<0)  // temporary: new expiration state
#define W_DELETE       (1<<1)  // ephemeral: flags propagation is a deletion
#define W_DEL(fn)      (1<<(2+(fn)))  // ephemeral: f/n message would be subject to expunge
#define W_UPGRADE      (1<<4)  // ephemeral: upgrading placeholder, do not apply MaxSize
#define W_PURGE        (1<<5)  // ephemeral: placeholder is being nuked

typedef struct sync_rec {
	struct sync_rec *next;
	/* string_list_t *keywords; */
	uint uid[2];
	message_t *msg[2];
	uchar status, wstate, flags, pflags, aflags[2], dflags[2];
	char tuid[TUIDL];
} sync_rec_t;

typedef struct {
	int t[2];
	void (*cb)( int sts, void *aux ), *aux;
	char *dname, *jname, *nname, *lname, *box_name[2];
	FILE *jfp, *nfp;
	sync_rec_t *srecs, **srecadd;
	channel_conf_t *chan;
	store_t *ctx[2];
	driver_t *drv[2];
	const char *orig_name[2];
	message_t *msgs[2], *new_msgs[2];
	uint_array_alloc_t trashed_msgs[2];
	int state[2], lfd, ret, existing, replayed;
	uint ref_count, nsrecs, opts[2];
	uint new_pending[2], flags_pending[2], trash_pending[2];
	uint maxuid[2];     // highest UID that was already propagated
	uint oldmaxuid[2];  // highest UID that was already propagated before this run
	uint uidval[2];     // UID validity value
	uint newuidval[2];  // UID validity obtained from driver
	uint finduid[2];    // TUID lookup makes sense only for UIDs >= this
	uint maxxfuid;      // highest expired UID on far side
	uint oldmaxxfuid;   // highest expired UID on far side before this run
	uchar good_flags[2], bad_flags[2];
} sync_vars_t;

static void sync_ref( sync_vars_t *svars ) { ++svars->ref_count; }
static void sync_deref( sync_vars_t *svars );
static int check_cancel( sync_vars_t *svars );

#define AUX &svars->t[t]
#define INV_AUX &svars->t[1-t]
#define DECL_SVARS \
	int t; \
	sync_vars_t *svars
#define INIT_SVARS(aux) \
	t = *(int *)aux; \
	svars = (sync_vars_t *)(((char *)(&((int *)aux)[-t])) - offsetof(sync_vars_t, t))
#define DECL_INIT_SVARS(aux) \
	int t = *(int *)aux; \
	sync_vars_t *svars = (sync_vars_t *)(((char *)(&((int *)aux)[-t])) - offsetof(sync_vars_t, t))

/* operation dependencies:
   select(x): -
   load(x): select(x)
   new(F), new(N), flags(F), flags(N): load(F) & load(N)
   find_new(x): new(x)
   trash(x): flags(x)
   close(x): trash(x) & find_new(x) & new(!x) // with expunge
   cleanup: close(F) & close(N)
*/

#define ST_LOADED          (1<<0)
#define ST_FIND_OLD        (1<<1)
#define ST_SENT_NEW        (1<<2)
#define ST_FIND_NEW        (1<<3)
#define ST_FOUND_NEW       (1<<4)
#define ST_SENT_FLAGS      (1<<5)
#define ST_SENT_TRASH      (1<<6)
#define ST_CLOSED          (1<<7)
#define ST_SENT_CANCEL     (1<<8)
#define ST_CANCELED        (1<<9)
#define ST_SELECTED        (1<<10)
#define ST_DID_EXPUNGE     (1<<11)
#define ST_CLOSING         (1<<12)
#define ST_CONFIRMED       (1<<13)
#define ST_PRESENT         (1<<14)
#define ST_SENDING_NEW     (1<<15)


static void
create_state( sync_vars_t *svars )
{
	if (!(svars->nfp = fopen( svars->nname, "w" ))) {
		sys_error( "Error: cannot create new sync state %s", svars->nname );
		exit( 1 );
	}
}

static void ATTR_PRINTFLIKE(2, 3)
jFprintf( sync_vars_t *svars, const char *msg, ... )
{
	va_list va;

	if (JLimit && !--JLimit)
		exit( 101 );
	if (!svars->jfp) {
		create_state( svars );
		if (!(svars->jfp = fopen( svars->jname, svars->replayed ? "a" : "w" ))) {
			sys_error( "Error: cannot create journal %s", svars->jname );
			exit( 1 );
		}
		setlinebuf( svars->jfp );
		if (!svars->replayed)
			Fprintf( svars->jfp, JOURNAL_VERSION "\n" );
	}
	va_start( va, msg );
	vFprintf( svars->jfp, msg, va );
	va_end( va );
	if (JLimit && !--JLimit)
		exit( 100 );
}

#define JLOG_(log_fmt, log_args, dbg_fmt, ...) \
	do { \
		debug( "-> log: " log_fmt " (" dbg_fmt ")\n", __VA_ARGS__ ); \
		jFprintf( svars, log_fmt "\n", deparen(log_args) ); \
	} while (0)
#define JLOG3(log_fmt, log_args, dbg_fmt) \
	JLOG_(log_fmt, log_args, dbg_fmt, deparen(log_args))
#define JLOG4(log_fmt, log_args, dbg_fmt, dbg_args) \
	JLOG_(log_fmt, log_args, dbg_fmt, deparen(log_args), deparen(dbg_args))
#define JLOG_SEL(_1, _2, _3, _4, x, ...) x
#define JLOG(...) JLOG_SEL(__VA_ARGS__, JLOG4, JLOG3, NO_JLOG2, NO_JLOG1)(__VA_ARGS__)

static void
assign_uid( sync_vars_t *svars, sync_rec_t *srec, int t, uint uid )
{
	srec->uid[t] = uid;
	if (uid == svars->maxuid[t] + 1)
		svars->maxuid[t] = uid;
	srec->status &= ~S_PENDING;
	srec->wstate &= ~W_UPGRADE;
	srec->tuid[0] = 0;
}

#define ASSIGN_UID(srec, t, nuid, ...) \
	do { \
		JLOG( "%c %u %u %u", ("<>"[t], srec->uid[F], srec->uid[N], nuid), __VA_ARGS__ ); \
		assign_uid( svars, srec, t, nuid ); \
	} while (0)

static void
match_tuids( sync_vars_t *svars, int t, message_t *msgs )
{
	sync_rec_t *srec;
	message_t *tmsg, *ntmsg = NULL;
	const char *diag;
	int num_lost = 0;

	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		if (!srec->uid[t] && srec->tuid[0]) {
			debug( "pair(%u,%u) TUID %." stringify(TUIDL) "s\n", srec->uid[F], srec->uid[N], srec->tuid );
			for (tmsg = ntmsg; tmsg; tmsg = tmsg->next) {
				if (tmsg->status & M_DEAD)
					continue;
				if (tmsg->tuid[0] && !memcmp( tmsg->tuid, srec->tuid, TUIDL )) {
					diag = (tmsg == ntmsg) ? "adjacently" : "after gap";
					goto mfound;
				}
			}
			for (tmsg = msgs; tmsg != ntmsg; tmsg = tmsg->next) {
				if (tmsg->status & M_DEAD)
					continue;
				if (tmsg->tuid[0] && !memcmp( tmsg->tuid, srec->tuid, TUIDL )) {
					diag = "after reset";
					goto mfound;
				}
			}
			JLOG( "& %u %u", (srec->uid[F], srec->uid[N]), "TUID lost" );
			// Note: status remains S_PENDING.
			srec->tuid[0] = 0;
			num_lost++;
			continue;
		  mfound:
			tmsg->srec = srec;
			srec->msg[t] = tmsg;
			ntmsg = tmsg->next;
			ASSIGN_UID( srec, t, tmsg->uid, "TUID matched %s", diag );
		}
	}
	if (num_lost)
		warn( "Warning: lost track of %d %sed message(s)\n", num_lost, str_hl[t] );
}


static uchar
sanitize_flags( uchar tflags, sync_vars_t *svars, int t )
{
	if (!(DFlags & QUIET)) {
		// We complain only once per flag per store - even though _theoretically_
		// each mailbox can support different flags according to the IMAP spec.
		uchar bflags = tflags & ~(svars->good_flags[t] | svars->bad_flags[t]);
		if (bflags) {
			char bfbuf[16];
			make_flags( bflags, bfbuf );
			notice( "Notice: %s store does not support flag(s) '%s'; not propagating.\n", str_fn[t], bfbuf );
			svars->bad_flags[t] |= bflags;
		}
	}
	return tflags & svars->good_flags[t];
}


typedef struct copy_vars {
	void (*cb)( int sts, uint uid, struct copy_vars *vars );
	void *aux;
	sync_rec_t *srec; /* also ->tuid */
	message_t *msg;
	msg_data_t data;
	int minimal;
} copy_vars_t;

static void msg_fetched( int sts, void *aux );

static void
copy_msg( copy_vars_t *vars )
{
	DECL_INIT_SVARS(vars->aux);

	t ^= 1;
	vars->data.flags = vars->msg->flags;
	vars->data.date = svars->chan->use_internal_date ? -1 : 0;
	svars->drv[t]->fetch_msg( svars->ctx[t], vars->msg, &vars->data, vars->minimal, msg_fetched, vars );
}

static void msg_stored( int sts, uint uid, void *aux );

static void
copy_msg_bytes( char **out_ptr, const char *in_buf, uint *in_idx, uint in_len, int in_cr, int out_cr )
{
	char *out = *out_ptr;
	uint idx = *in_idx;
	if (out_cr != in_cr) {
		char c;
		if (out_cr) {
			for (; idx < in_len; idx++) {
				if ((c = in_buf[idx]) != '\r') {
					if (c == '\n')
						*out++ = '\r';
					*out++ = c;
				}
			}
		} else {
			for (; idx < in_len; idx++) {
				if ((c = in_buf[idx]) != '\r')
					*out++ = c;
			}
		}
	} else {
		memcpy( out, in_buf + idx, in_len - idx );
		out += in_len - idx;
		idx = in_len;
	}
	*out_ptr = out;
	*in_idx = idx;
}

static int
copy_msg_convert( int in_cr, int out_cr, copy_vars_t *vars, int t )
{
	char *in_buf = vars->data.data;
	uint in_len = vars->data.len;
	uint idx = 0, sbreak = 0, ebreak = 0, break2 = UINT_MAX;
	uint lines = 0, hdr_crs = 0, bdy_crs = 0, app_cr = 0, extra = 0;
	uint add_subj = 0;

	if (vars->srec) {
	  nloop: ;
		uint start = idx;
		uint line_crs = 0;
		while (idx < in_len) {
			char c = in_buf[idx++];
			if (c == '\r') {
				line_crs++;
			} else if (c == '\n') {
				if (!ebreak && starts_with_upper( in_buf + start, (int)(in_len - start), "X-TUID: ", 8 )) {
					extra = (sbreak = start) - (ebreak = idx);
					if (!vars->minimal)
						goto oke;
				} else {
					if (break2 == UINT_MAX && vars->minimal &&
					    starts_with_upper( in_buf + start, (int)(in_len - start), "SUBJECT:", 8 )) {
						break2 = start + 8;
						if (break2 < in_len && in_buf[break2] == ' ')
							break2++;
					}
					lines++;
					hdr_crs += line_crs;
				}
				if (idx - line_crs - 1 == start) {
					if (!ebreak)
						sbreak = ebreak = start;
					if (vars->minimal) {
						in_len = idx;
						if (break2 == UINT_MAX) {
							break2 = start;
							add_subj = 1;
						}
					}
					goto oke;
				}
				goto nloop;
			}
		}
		warn( "Warning: message %u from %s has incomplete header; skipping.\n",
		      vars->msg->uid, str_fn[1-t] );
		free( in_buf );
		return 0;
	  oke:
		app_cr = out_cr && (!in_cr || hdr_crs);
		extra += 8 + TUIDL + app_cr + 1;
	}
	if (out_cr != in_cr) {
		for (; idx < in_len; idx++) {
			char c = in_buf[idx];
			if (c == '\r')
				bdy_crs++;
			else if (c == '\n')
				lines++;
		}
		extra -= hdr_crs + bdy_crs;
		if (out_cr)
			extra += lines;
	}

	uint dummy_msg_len = 0;
	char dummy_msg_buf[180];
	static const char dummy_pfx[] = "[placeholder] ";
	static const char dummy_subj[] = "Subject: [placeholder] (No Subject)";
	static const char dummy_msg[] =
		"Having a size of %s, this message is over the MaxSize limit.%s"
		"Flag it and sync again (Sync mode ReNew) to fetch its real contents.%s";

	if (vars->minimal) {
		char sz[32];

		if (vars->msg->size < 1024000)
			sprintf( sz, "%dKiB", (int)(vars->msg->size >> 10) );
		else
			sprintf( sz, "%.1fMiB", vars->msg->size / 1048576. );
		const char *nl = app_cr ? "\r\n" : "\n";
		dummy_msg_len = (uint)sprintf( dummy_msg_buf, dummy_msg, sz, nl, nl );
		extra += dummy_msg_len;
		extra += add_subj ? strlen(dummy_subj) + app_cr + 1 : strlen(dummy_pfx);
	}

	vars->data.len = in_len + extra;
	if (vars->data.len > INT_MAX) {
		warn( "Warning: message %u from %s is too big after conversion; skipping.\n",
		      vars->msg->uid, str_fn[1-t] );
		free( in_buf );
		return 0;
	}
	char *out_buf = vars->data.data = nfmalloc( vars->data.len );
	idx = 0;
	if (vars->srec) {
		if (break2 < sbreak) {
			copy_msg_bytes( &out_buf, in_buf, &idx, break2, in_cr, out_cr );
			memcpy( out_buf, dummy_pfx, strlen(dummy_pfx) );
			out_buf += strlen(dummy_pfx);
		}
		copy_msg_bytes( &out_buf, in_buf, &idx, sbreak, in_cr, out_cr );

		memcpy( out_buf, "X-TUID: ", 8 );
		out_buf += 8;
		memcpy( out_buf, vars->srec->tuid, TUIDL );
		out_buf += TUIDL;
		if (app_cr)
			*out_buf++ = '\r';
		*out_buf++ = '\n';
		idx = ebreak;

		if (break2 != UINT_MAX && break2 >= sbreak) {
			copy_msg_bytes( &out_buf, in_buf, &idx, break2, in_cr, out_cr );
			if (!add_subj) {
				memcpy( out_buf, dummy_pfx, strlen(dummy_pfx) );
				out_buf += strlen(dummy_pfx);
			} else {
				memcpy( out_buf, dummy_subj, strlen(dummy_subj) );
				out_buf += strlen(dummy_subj);
				if (app_cr)
					*out_buf++ = '\r';
				*out_buf++ = '\n';
			}
		}
	}
	copy_msg_bytes( &out_buf, in_buf, &idx, in_len, in_cr, out_cr );

	if (vars->minimal)
		memcpy( out_buf, dummy_msg_buf, dummy_msg_len );

	free( in_buf );
	return 1;
}

static void
msg_fetched( int sts, void *aux )
{
	copy_vars_t *vars = (copy_vars_t *)aux;
	DECL_SVARS;
	int scr, tcr;

	switch (sts) {
	case DRV_OK:
		INIT_SVARS(vars->aux);
		if (check_cancel( svars )) {
			free( vars->data.data );
			vars->cb( SYNC_CANCELED, 0, vars );
			return;
		}

		vars->msg->flags = vars->data.flags = sanitize_flags( vars->data.flags, svars, t );

		scr = (svars->drv[1-t]->get_caps( svars->ctx[1-t] ) / DRV_CRLF) & 1;
		tcr = (svars->drv[t]->get_caps( svars->ctx[t] ) / DRV_CRLF) & 1;
		if (vars->srec || scr != tcr) {
			if (!copy_msg_convert( scr, tcr, vars, t )) {
				vars->cb( SYNC_NOGOOD, 0, vars );
				return;
			}
		}

		svars->drv[t]->store_msg( svars->ctx[t], &vars->data, !vars->srec, msg_stored, vars );
		break;
	case DRV_CANCELED:
		vars->cb( SYNC_CANCELED, 0, vars );
		break;
	case DRV_MSG_BAD:
		vars->cb( SYNC_NOGOOD, 0, vars );
		break;
	default:
		vars->cb( SYNC_FAIL, 0, vars );
		break;
	}
}

static void
msg_stored( int sts, uint uid, void *aux )
{
	copy_vars_t *vars = (copy_vars_t *)aux;
	DECL_SVARS;

	switch (sts) {
	case DRV_OK:
		vars->cb( SYNC_OK, uid, vars );
		break;
	case DRV_CANCELED:
		vars->cb( SYNC_CANCELED, 0, vars );
		break;
	case DRV_MSG_BAD:
		INIT_SVARS(vars->aux);
		(void)svars;
		warn( "Warning: %s refuses to store message %u from %s.\n",
		      str_fn[t], vars->msg->uid, str_fn[1-t] );
		vars->cb( SYNC_NOGOOD, 0, vars );
		break;
	default:
		vars->cb( SYNC_FAIL, 0, vars );
		break;
	}
}


static void sync_bail( sync_vars_t *svars );
static void sync_bail2( sync_vars_t *svars );
static void sync_bail3( sync_vars_t *svars );
static void cancel_done( void *aux );

static void
cancel_sync( sync_vars_t *svars )
{
	int t;

	for (t = 0; t < 2; t++) {
		int other_state = svars->state[1-t];
		if (svars->ret & SYNC_BAD(t)) {
			cancel_done( AUX );
		} else if (!(svars->state[t] & ST_SENT_CANCEL)) {
			/* ignore subsequent failures from in-flight commands */
			svars->state[t] |= ST_SENT_CANCEL;
			svars->drv[t]->cancel_cmds( svars->ctx[t], cancel_done, AUX );
		}
		if (other_state & ST_CANCELED)
			break;
	}
}

static void
cancel_done( void *aux )
{
	DECL_INIT_SVARS(aux);

	svars->state[t] |= ST_CANCELED;
	if (svars->state[1-t] & ST_CANCELED) {
		if (svars->nfp) {
			Fclose( svars->nfp, 0 );
			Fclose( svars->jfp, 0 );
		}
		sync_bail( svars );
	}
}

static void
store_bad( void *aux )
{
	DECL_INIT_SVARS(aux);

	svars->drv[t]->cancel_store( svars->ctx[t] );
	svars->ret |= SYNC_BAD(t);
	cancel_sync( svars );
}

static int
check_cancel( sync_vars_t *svars )
{
	return (svars->state[F] | svars->state[N]) & (ST_SENT_CANCEL | ST_CANCELED);
}

static int
check_ret( int sts, void *aux )
{
	DECL_SVARS;

	if (sts == DRV_CANCELED)
		return 1;
	INIT_SVARS(aux);
	if (sts == DRV_BOX_BAD) {
		svars->ret |= SYNC_FAIL;
		cancel_sync( svars );
		return 1;
	}
	return check_cancel( svars );
}

#define SVARS_CHECK_RET \
	DECL_SVARS; \
	if (check_ret( sts, aux )) \
		return; \
	INIT_SVARS(aux)

#define SVARS_CHECK_RET_VARS(type) \
	type *vars = (type *)aux; \
	DECL_SVARS; \
	if (check_ret( sts, vars->aux )) { \
		free( vars ); \
		return; \
	} \
	INIT_SVARS(vars->aux)

#define SVARS_CHECK_CANCEL_RET \
	DECL_SVARS; \
	if (sts == SYNC_CANCELED) { \
		free( vars ); \
		return; \
	} \
	INIT_SVARS(vars->aux)

static char *
clean_strdup( const char *s )
{
	char *cs;
	uint i;

	cs = nfstrdup( s );
	for (i = 0; cs[i]; i++)
		if (cs[i] == '/')
			cs[i] = '!';
	return cs;
}


static sync_rec_t *
upgrade_srec( sync_vars_t *svars, sync_rec_t *srec )
{
	// Create an entry and append it to the current one.
	sync_rec_t *nsrec = nfcalloc( sizeof(*nsrec) );
	nsrec->next = srec->next;
	srec->next = nsrec;
	if (svars->srecadd == &srec->next)
		svars->srecadd = &nsrec->next;
	// Move the placeholder to the new entry.
	int t = (srec->status & S_DUMMY(F)) ? F : N;
	nsrec->uid[t] = srec->uid[t];
	srec->uid[t] = 0;
	if (srec->msg[t]) {  // NULL during journal replay; is assigned later.
		nsrec->msg[t] = srec->msg[t];
		nsrec->msg[t]->srec = nsrec;
		srec->msg[t] = NULL;
	}
	// Mark the original entry for upgrade.
	srec->status = (srec->status & ~(S_DUMMY(F)|S_DUMMY(N))) | S_PENDING;
	srec->wstate |= W_UPGRADE;
	// Mark the placeholder for nuking.
	nsrec->wstate = W_PURGE;
	nsrec->aflags[t] = F_DELETED;
	return nsrec;
}

static int
prepare_state( sync_vars_t *svars )
{
	char *s, *cmname, *csname;
	channel_conf_t *chan;

	chan = svars->chan;
	if (!strcmp( chan->sync_state ? chan->sync_state : global_conf.sync_state, "*" )) {
		const char *path = svars->drv[N]->get_box_path( svars->ctx[N] );
		if (!path) {
			error( "Error: store '%s' does not support in-box sync state\n", chan->stores[N]->name );
			return 0;
		}
		nfasprintf( &svars->dname, "%s/." EXE "state", path );
	} else {
		csname = clean_strdup( svars->box_name[N] );
		if (chan->sync_state)
			nfasprintf( &svars->dname, "%s%s", chan->sync_state, csname );
		else {
			char c = FieldDelimiter;
			cmname = clean_strdup( svars->box_name[F] );
			nfasprintf( &svars->dname, "%s%c%s%c%s_%c%s%c%s", global_conf.sync_state,
			            c, chan->stores[F]->name, c, cmname, c, chan->stores[N]->name, c, csname );
			free( cmname );
		}
		free( csname );
		if (!(s = strrchr( svars->dname, '/' ))) {
			error( "Error: invalid SyncState location '%s'\n", svars->dname );
			return 0;
		}
		*s = 0;
		if (mkdir( svars->dname, 0700 ) && errno != EEXIST) {
			sys_error( "Error: cannot create SyncState directory '%s'", svars->dname );
			return 0;
		}
		*s = '/';
	}
	nfasprintf( &svars->jname, "%s.journal", svars->dname );
	nfasprintf( &svars->nname, "%s.new", svars->dname );
	nfasprintf( &svars->lname, "%s.lock", svars->dname );
	return 1;
}

static int
lock_state( sync_vars_t *svars )
{
	struct flock lck;

	if (svars->lfd >= 0)
		return 1;
	memset( &lck, 0, sizeof(lck) );
#if SEEK_SET != 0
	lck.l_whence = SEEK_SET;
#endif
#if F_WRLCK != 0
	lck.l_type = F_WRLCK;
#endif
	if ((svars->lfd = open( svars->lname, O_WRONLY|O_CREAT, 0666 )) < 0) {
		sys_error( "Error: cannot create lock file %s", svars->lname );
		return 0;
	}
	if (fcntl( svars->lfd, F_SETLK, &lck )) {
		error( "Error: channel :%s:%s-:%s:%s is locked\n",
		       svars->chan->stores[F]->name, svars->orig_name[F], svars->chan->stores[N]->name, svars->orig_name[N] );
		close( svars->lfd );
		svars->lfd = -1;
		return 0;
	}
	return 1;
}

static void
save_state( sync_vars_t *svars )
{
	sync_rec_t *srec;
	char fbuf[16]; /* enlarge when support for keywords is added */

	// If no change was made, the state is also unmodified.
	if (!svars->jfp && !svars->replayed)
		return;

	if (!svars->nfp)
		create_state( svars );
	Fprintf( svars->nfp,
	         "FarUidValidity %u\nNearUidValidity %u\nMaxPulledUid %u\nMaxPushedUid %u\n",
	         svars->uidval[F], svars->uidval[N], svars->maxuid[F], svars->maxuid[N] );
	if (svars->maxxfuid)
		Fprintf( svars->nfp, "MaxExpiredFarUid %u\n", svars->maxxfuid );
	Fprintf( svars->nfp, "\n" );
	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		make_flags( srec->flags, fbuf );
		Fprintf( svars->nfp, "%u %u %s%s%s\n", srec->uid[F], srec->uid[N],
		         (srec->status & S_DUMMY(F)) ? "<" : (srec->status & S_DUMMY(N)) ? ">" : "",
		         (srec->status & S_SKIPPED) ? "^" : (srec->status & S_EXPIRED) ? "~" : "", fbuf );
	}

	Fclose( svars->nfp, 1 );
	if (svars->jfp)
		Fclose( svars->jfp, 0 );
	if (!(DFlags & KEEPJOURNAL)) {
		/* order is important! */
		if (rename( svars->nname, svars->dname ))
			warn( "Warning: cannot commit sync state %s\n", svars->dname );
		else if (unlink( svars->jname ))
			warn( "Warning: cannot delete journal %s\n", svars->jname );
	}
}

static int
load_state( sync_vars_t *svars )
{
	sync_rec_t *srec, *nsrec;
	char *s;
	FILE *jfp;
	uint ll;
	uint maxxnuid = 0;
	char c;
	struct stat st;
	char fbuf[16]; /* enlarge when support for keywords is added */
	char buf[128], buf1[64], buf2[64];

	if ((jfp = fopen( svars->dname, "r" ))) {
		if (!lock_state( svars ))
			goto jbail;
		debug( "reading sync state %s ...\n", svars->dname );
		int line = 0;
		while (fgets( buf, sizeof(buf), jfp )) {
			line++;
			if (!(ll = strlen( buf )) || buf[ll - 1] != '\n') {
				error( "Error: incomplete sync state header entry at %s:%d\n", svars->dname, line );
			  jbail:
				fclose( jfp );
				return 0;
			}
			if (ll == 1)
				goto gothdr;
			if (line == 1 && isdigit( buf[0] )) {  // Pre-1.1 legacy
				if (sscanf( buf, "%63s %63s", buf1, buf2 ) != 2 ||
				    sscanf( buf1, "%u:%u", &svars->uidval[F], &svars->maxuid[F] ) < 2 ||
				    sscanf( buf2, "%u:%u:%u", &svars->uidval[N], &maxxnuid, &svars->maxuid[N] ) < 3) {
					error( "Error: invalid sync state header in %s\n", svars->dname );
					goto jbail;
				}
				goto gothdr;
			}
			uint uid;
			if (sscanf( buf, "%63s %u", buf1, &uid ) != 2) {
				error( "Error: malformed sync state header entry at %s:%d\n", svars->dname, line );
				goto jbail;
			}
			if (!strcmp( buf1, "FarUidValidity" ) || !strcmp( buf1, "MasterUidValidity" ) /* Pre-1.4 legacy */)
				svars->uidval[F] = uid;
			else if (!strcmp( buf1, "NearUidValidity" ) || !strcmp( buf1, "SlaveUidValidity" ) /* Pre-1.4 legacy */)
				svars->uidval[N] = uid;
			else if (!strcmp( buf1, "MaxPulledUid" ))
				svars->maxuid[F] = uid;
			else if (!strcmp( buf1, "MaxPushedUid" ))
				svars->maxuid[N] = uid;
			else if (!strcmp( buf1, "MaxExpiredFarUid" ) || !strcmp( buf1, "MaxExpiredMasterUid" ) /* Pre-1.4 legacy */)
				svars->maxxfuid = uid;
			else if (!strcmp( buf1, "MaxExpiredSlaveUid" ))  // Pre-1.3 legacy
				maxxnuid = uid;
			else {
				error( "Error: unrecognized sync state header entry at %s:%d\n", svars->dname, line );
				goto jbail;
			}
		}
		error( "Error: unterminated sync state header in %s\n", svars->dname );
		goto jbail;
	  gothdr:
		while (fgets( buf, sizeof(buf), jfp )) {
			line++;
			if (!(ll = strlen( buf )) || buf[--ll] != '\n') {
				error( "Error: incomplete sync state entry at %s:%d\n", svars->dname, line );
				goto jbail;
			}
			buf[ll] = 0;
			fbuf[0] = 0;
			uint t1, t2;
			if (sscanf( buf, "%u %u %15s", &t1, &t2, fbuf ) < 2) {
				error( "Error: invalid sync state entry at %s:%d\n", svars->dname, line );
				goto jbail;
			}
			srec = nfcalloc( sizeof(*srec) );
			srec->uid[F] = t1;
			srec->uid[N] = t2;
			s = fbuf;
			if (*s == '<') {
				s++;
				srec->status = S_DUMMY(F);
			} else if (*s == '>') {
				s++;
				srec->status = S_DUMMY(N);
			}
			if (*s == '^') {  // Pre-1.4 legacy
				s++;
				srec->status = S_SKIPPED;
			} else if (*s == '~' || *s == 'X' /* Pre-1.3 legacy */) {
				s++;
				srec->status = S_EXPIRE | S_EXPIRED;
			} else if (srec->uid[F] == (uint)-1) {  // Pre-1.3 legacy
				srec->uid[F] = 0;
				srec->status = S_SKIPPED;
			} else if (srec->uid[N] == (uint)-1) {
				srec->uid[N] = 0;
				srec->status = S_SKIPPED;
			}
			srec->flags = parse_flags( s );
			debug( "  entry (%u,%u,%u,%s%s)\n", srec->uid[F], srec->uid[N], srec->flags,
			       (srec->status & S_SKIPPED) ? "SKIP" : (srec->status & S_EXPIRED) ? "XPIRE" : "",
			       (srec->status & S_DUMMY(F)) ? ",F-DUMMY" : (srec->status & S_DUMMY(N)) ? ",N-DUMMY" : "" );
			*svars->srecadd = srec;
			svars->srecadd = &srec->next;
			svars->nsrecs++;
		}
		fclose( jfp );
		svars->existing = 1;
	} else {
		if (errno != ENOENT) {
			sys_error( "Error: cannot read sync state %s", svars->dname );
			return 0;
		}
		svars->existing = 0;
	}

	// This is legacy support for pre-1.3 sync states.
	if (maxxnuid) {
		uint minwuid = UINT_MAX;
		for (srec = svars->srecs; srec; srec = srec->next) {
			if ((srec->status & (S_DEAD | S_SKIPPED | S_PENDING)) || !srec->uid[F])
				continue;
			if (srec->status & S_EXPIRED) {
				if (!srec->uid[N]) {
					// The expired message was already gone.
					continue;
				}
				// The expired message was not expunged yet, so re-examine it.
				// This will happen en masse, so just extend the bulk fetch.
			} else {
				if (srec->uid[N] && maxxnuid >= srec->uid[N]) {
					// The non-expired message is in the generally expired range,
					// so don't make it contribute to the bulk fetch.
					continue;
				}
				// Usual non-expired message.
			}
			if (minwuid > srec->uid[F])
				minwuid = srec->uid[F];
		}
		svars->maxxfuid = minwuid - 1;
	}

	int line = 0;
	if ((jfp = fopen( svars->jname, "r" ))) {
		if (!lock_state( svars ))
			goto jbail;
		if (!stat( svars->nname, &st ) && fgets( buf, sizeof(buf), jfp )) {
			debug( "recovering journal ...\n" );
			if (!(ll = strlen( buf )) || buf[--ll] != '\n') {
				error( "Error: incomplete journal header in %s\n", svars->jname );
				goto jbail;
			}
			buf[ll] = 0;
			if (!equals( buf, (int)ll, JOURNAL_VERSION, strlen(JOURNAL_VERSION) )) {
				error( "Error: incompatible journal version "
				                 "(got %s, expected " JOURNAL_VERSION ")\n", buf );
				goto jbail;
			}
			srec = NULL;
			line = 1;
			while (fgets( buf, sizeof(buf), jfp )) {
				line++;
				if (!(ll = strlen( buf )) || buf[--ll] != '\n') {
					error( "Error: incomplete journal entry at %s:%d\n", svars->jname, line );
					goto jbail;
				}
				buf[ll] = 0;
				int tn;
				uint t1, t2, t3, t4;
				if ((c = buf[0]) == '#' ?
				      (tn = 0, (sscanf( buf + 2, "%u %u %n", &t1, &t2, &tn ) < 2) || !tn || (ll - (uint)tn != TUIDL + 2)) :
				      c == '!' ?
				        (sscanf( buf + 2, "%u", &t1 ) != 1) :
				        c == 'N' || c == 'F' || c == 'T' || c == '+' || c == '&' || c == '-' || c == '=' || c == '_' || c == '|' ?
				          (sscanf( buf + 2, "%u %u", &t1, &t2 ) != 2) :
				          c != '^' ?
				            (sscanf( buf + 2, "%u %u %u", &t1, &t2, &t3 ) != 3) :
				            (sscanf( buf + 2, "%u %u %u %u", &t1, &t2, &t3, &t4 ) != 4))
				{
					error( "Error: malformed journal entry at %s:%d\n", svars->jname, line );
					goto jbail;
				}
				if (c == 'N')
					svars->maxuid[t1] = t2;
				else if (c == 'F')
					svars->finduid[t1] = t2;
				else if (c == 'T')
					*uint_array_append( &svars->trashed_msgs[t1] ) = t2;
				else if (c == '!')
					svars->maxxfuid = t1;
				else if (c == '|') {
					svars->uidval[F] = t1;
					svars->uidval[N] = t2;
				} else if (c == '+') {
					srec = nfcalloc( sizeof(*srec) );
					srec->uid[F] = t1;
					srec->uid[N] = t2;
					debug( "  new entry(%u,%u)\n", t1, t2 );
					srec->status = S_PENDING;
					*svars->srecadd = srec;
					svars->srecadd = &srec->next;
					svars->nsrecs++;
				} else {
					for (nsrec = srec; srec; srec = srec->next)
						if (srec->uid[F] == t1 && srec->uid[N] == t2)
							goto syncfnd;
					for (srec = svars->srecs; srec != nsrec; srec = srec->next)
						if (srec->uid[F] == t1 && srec->uid[N] == t2)
							goto syncfnd;
					error( "Error: journal entry at %s:%d refers to non-existing sync state entry\n", svars->jname, line );
					goto jbail;
				  syncfnd:
					debugn( "  entry(%u,%u,%u) ", srec->uid[F], srec->uid[N], srec->flags );
					switch (c) {
					case '-':
						debug( "killed\n" );
						srec->status = S_DEAD;
						break;
					case '=':
						debug( "aborted\n" );
						if (svars->maxxfuid < srec->uid[F])
							svars->maxxfuid = srec->uid[F];
						srec->status = S_DEAD;
						break;
					case '#':
						memcpy( srec->tuid, buf + tn + 2, TUIDL );
						debug( "TUID now %." stringify(TUIDL) "s\n", srec->tuid );
						break;
					case '&':
						debug( "TUID %." stringify(TUIDL) "s lost\n", srec->tuid );
						srec->tuid[0] = 0;
						break;
					case '<':
						debug( "far side now %u\n", t3 );
						assign_uid( svars, srec, F, t3 );
						break;
					case '>':
						debug( "near side now %u\n", t3 );
						assign_uid( svars, srec, N, t3 );
						break;
					case '*':
						debug( "flags now %u\n", t3 );
						srec->flags = (uchar)t3;
						srec->aflags[F] = srec->aflags[N] = 0;
						srec->wstate &= ~W_PURGE;
						break;
					case '~':
						debug( "status now %#x\n", t3 );
						srec->status = (uchar)t3;
						break;
					case '_':
						debug( "has placeholder now\n" );
						srec->status = S_PENDING;  // Pre-1.4 legacy only
						srec->status |= !srec->uid[F] ? S_DUMMY(F) : S_DUMMY(N);
						break;
					case '^':
						debug( "is being upgraded, flags %u, srec flags %u\n", t3, t4 );
						srec->pflags = (uchar)t3;
						srec->flags = (uchar)t4;
						srec = upgrade_srec( svars, srec );
						break;
					default:
						error( "Error: unrecognized journal entry at %s:%d\n", svars->jname, line );
						goto jbail;
					}
				}
			}
		}
		fclose( jfp );
	} else {
		if (errno != ENOENT) {
			sys_error( "Error: cannot read journal %s", svars->jname );
			return 0;
		}
	}
	svars->replayed = line;

	return 1;
}

static void
delete_state( sync_vars_t *svars )
{
	unlink( svars->nname );
	unlink( svars->jname );
	if (unlink( svars->dname ) || unlink( svars->lname )) {
		sys_error( "Error: channel %s: sync state cannot be deleted", svars->chan->name );
		svars->ret = SYNC_FAIL;
	}
}

static void box_confirmed( int sts, uint uidvalidity, void *aux );
static void box_confirmed2( sync_vars_t *svars, int t );
static void box_deleted( int sts, void *aux );
static void box_created( int sts, void *aux );
static void box_opened( int sts, uint uidvalidity, void *aux );
static void box_opened2( sync_vars_t *svars, int t );
static void load_box( sync_vars_t *svars, int t, uint minwuid, uint_array_t mexcs );

void
sync_boxes( store_t *ctx[], const char * const names[], int present[], channel_conf_t *chan,
            void (*cb)( int sts, void *aux ), void *aux )
{
	sync_vars_t *svars;
	int t;

	svars = nfcalloc( sizeof(*svars) );
	svars->t[1] = 1;
	svars->ref_count = 1;
	svars->cb = cb;
	svars->aux = aux;
	svars->ctx[0] = ctx[0];
	svars->ctx[1] = ctx[1];
	svars->chan = chan;
	svars->lfd = -1;
	svars->uidval[0] = svars->uidval[1] = UIDVAL_BAD;
	svars->srecadd = &svars->srecs;

	for (t = 0; t < 2; t++) {
		svars->orig_name[t] =
			(!names[t] || (ctx[t]->conf->map_inbox && !strcmp( ctx[t]->conf->map_inbox, names[t] ))) ?
				"INBOX" : names[t];
		if (!ctx[t]->conf->flat_delim[0]) {
			svars->box_name[t] = nfstrdup( svars->orig_name[t] );
		} else if (map_name( svars->orig_name[t], &svars->box_name[t], 0, "/", ctx[t]->conf->flat_delim ) < 0) {
			error( "Error: canonical mailbox name '%s' contains flattened hierarchy delimiter\n", svars->orig_name[t] );
		  bail3:
			svars->ret = SYNC_FAIL;
			sync_bail3( svars );
			return;
		}
		svars->drv[t] = ctx[t]->driver;
		svars->drv[t]->set_bad_callback( ctx[t], store_bad, AUX );
	}
	/* Both boxes must be fully set up at this point, so that error exit paths
	 * don't run into uninitialized variables. */
	for (t = 0; t < 2; t++) {
		switch (svars->drv[t]->select_box( ctx[t], svars->box_name[t] )) {
		case DRV_STORE_BAD:
			store_bad( AUX );
			return;
		case DRV_BOX_BAD:
			goto bail3;
		}
	}

	if (!prepare_state( svars )) {
		svars->ret = SYNC_FAIL;
		sync_bail2( svars );
		return;
	}
	if (!load_state( svars )) {
		svars->ret = SYNC_FAIL;
		sync_bail( svars );
		return;
	}

	sync_ref( svars );
	for (t = 0; ; t++) {
		info( "Opening %s box %s...\n", str_fn[t], svars->orig_name[t] );
		if (present[t] == BOX_ABSENT)
			box_confirmed2( svars, t );
		else
			svars->drv[t]->open_box( ctx[t], box_confirmed, AUX );
		if (t || check_cancel( svars ))
			break;
	}
	sync_deref( svars );
}

static void
box_confirmed( int sts, uint uidvalidity, void *aux )
{
	DECL_SVARS;

	if (sts == DRV_CANCELED)
		return;
	INIT_SVARS(aux);
	if (check_cancel( svars ))
		return;

	if (sts == DRV_OK) {
		svars->state[t] |= ST_PRESENT;
		svars->newuidval[t] = uidvalidity;
	}
	box_confirmed2( svars, t );
}

static void
box_confirmed2( sync_vars_t *svars, int t )
{
	svars->state[t] |= ST_CONFIRMED;
	if (!(svars->state[1-t] & ST_CONFIRMED))
		return;

	sync_ref( svars );
	for (t = 0; ; t++) {
		if (!(svars->state[t] & ST_PRESENT)) {
			if (!(svars->state[1-t] & ST_PRESENT)) {
				if (!svars->existing) {
					error( "Error: channel %s: both far side %s and near side %s cannot be opened.\n",
					       svars->chan->name, svars->orig_name[F], svars->orig_name[N] );
				  bail:
					svars->ret = SYNC_FAIL;
				} else {
					/* This can legitimately happen if a deletion propagation was interrupted.
					 * We have no place to record this transaction, so we just assume it.
					 * Of course this bears the danger of clearing the state if both mailboxes
					 * temorarily cannot be opened for some weird reason (while the stores can). */
					delete_state( svars );
				}
			  done:
				sync_bail( svars );
				break;
			}
			if (svars->existing) {
				if (!(svars->chan->ops[1-t] & OP_REMOVE)) {
					error( "Error: channel %s: %s box %s cannot be opened.\n",
					       svars->chan->name, str_fn[t], svars->orig_name[t] );
					goto bail;
				}
				if (svars->drv[1-t]->confirm_box_empty( svars->ctx[1-t] ) != DRV_OK) {
					warn( "Warning: channel %s: %s box %s cannot be opened and %s box %s is not empty.\n",
					      svars->chan->name, str_fn[t], svars->orig_name[t], str_fn[1-t], svars->orig_name[1-t] );
					goto done;
				}
				info( "Deleting %s box %s...\n", str_fn[1-t], svars->orig_name[1-t] );
				svars->drv[1-t]->delete_box( svars->ctx[1-t], box_deleted, INV_AUX );
			} else {
				if (!(svars->chan->ops[t] & OP_CREATE)) {
					box_opened( DRV_BOX_BAD, UIDVAL_BAD, AUX );
				} else {
					info( "Creating %s box %s...\n", str_fn[t], svars->orig_name[t] );
					svars->drv[t]->create_box( svars->ctx[t], box_created, AUX );
				}
			}
		} else {
			box_opened2( svars, t );
		}
		if (t || check_cancel( svars ))
			break;
	}
	sync_deref( svars );
}

static void
box_deleted( int sts, void *aux )
{
	DECL_SVARS;

	if (check_ret( sts, aux ))
		return;
	INIT_SVARS(aux);

	delete_state( svars );
	svars->drv[t]->finish_delete_box( svars->ctx[t] );
	sync_bail( svars );
}

static void
box_created( int sts, void *aux )
{
	DECL_SVARS;

	if (check_ret( sts, aux ))
		return;
	INIT_SVARS(aux);

	svars->drv[t]->open_box( svars->ctx[t], box_opened, AUX );
}

static void
box_opened( int sts, uint uidvalidity, void *aux )
{
	DECL_SVARS;

	if (sts == DRV_CANCELED)
		return;
	INIT_SVARS(aux);
	if (check_cancel( svars ))
		return;

	if (sts == DRV_BOX_BAD) {
		error( "Error: channel %s: %s box %s cannot be opened.\n",
		       svars->chan->name, str_fn[t], svars->orig_name[t] );
		svars->ret = SYNC_FAIL;
		sync_bail( svars );
	} else {
		svars->newuidval[t] = uidvalidity;
		box_opened2( svars, t );
	}
}

static void
box_opened2( sync_vars_t *svars, int t )
{
	store_t *ctx[2];
	channel_conf_t *chan;
	sync_rec_t *srec;
	uint_array_alloc_t mexcs;
	uint opts[2], fails, minwuid;

	svars->state[t] |= ST_SELECTED;
	if (!(svars->state[1-t] & ST_SELECTED))
		return;
	ctx[0] = svars->ctx[0];
	ctx[1] = svars->ctx[1];
	chan = svars->chan;

	fails = 0;
	for (t = 0; t < 2; t++)
		if (svars->uidval[t] != UIDVAL_BAD && svars->uidval[t] != svars->newuidval[t])
			fails++;
	// If only one side changed UIDVALIDITY, we will try to re-approve it further down.
	if (fails == 2) {
		error( "Error: channel %s: UIDVALIDITY of both far side %s and near side %s changed.\n",
		       svars->chan->name, svars->orig_name[F], svars->orig_name[N]);
	  bail:
		svars->ret = SYNC_FAIL;
		sync_bail( svars );
		return;
	}

	if (!lock_state( svars ))
		goto bail;

	opts[F] = opts[N] = 0;
	if (fails)
		opts[F] = opts[N] = OPEN_OLD|OPEN_OLD_IDS;
	for (t = 0; t < 2; t++) {
		if (chan->ops[t] & (OP_DELETE|OP_FLAGS)) {
			opts[t] |= OPEN_SETFLAGS;
			opts[1-t] |= OPEN_OLD;
			if (chan->ops[t] & OP_FLAGS)
				opts[1-t] |= OPEN_FLAGS;
		}
		if (chan->ops[t] & (OP_NEW|OP_RENEW)) {
			opts[t] |= OPEN_APPEND;
			if (chan->ops[t] & OP_NEW) {
				opts[1-t] |= OPEN_NEW;
				if (chan->stores[t]->max_size != UINT_MAX)
					opts[1-t] |= OPEN_FLAGS|OPEN_NEW_SIZE;
			}
			if (chan->ops[t] & OP_RENEW) {
				opts[t] |= OPEN_OLD|OPEN_FLAGS|OPEN_SETFLAGS;
				opts[1-t] |= OPEN_OLD|OPEN_FLAGS;
			}
			if (chan->ops[t] & OP_EXPUNGE)  // Don't propagate doomed msgs
				opts[1-t] |= OPEN_FLAGS;
		}
		if (chan->ops[t] & OP_EXPUNGE) {
			opts[t] |= OPEN_EXPUNGE;
			if (chan->stores[t]->trash) {
				if (!chan->stores[t]->trash_only_new)
					opts[t] |= OPEN_OLD;
				opts[t] |= OPEN_NEW|OPEN_FLAGS;
			} else if (chan->stores[1-t]->trash && chan->stores[1-t]->trash_remote_new)
				opts[t] |= OPEN_NEW|OPEN_FLAGS;
		}
	}
	if ((chan->ops[N] & (OP_NEW|OP_RENEW|OP_FLAGS)) && chan->max_messages)
		opts[N] |= OPEN_OLD|OPEN_NEW|OPEN_FLAGS;
	if (svars->replayed)
		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (srec->tuid[0]) {
				if (!srec->uid[F])
					opts[F] |= OPEN_NEW|OPEN_FIND, svars->state[F] |= ST_FIND_OLD;
				else if (!srec->uid[N])
					opts[N] |= OPEN_NEW|OPEN_FIND, svars->state[N] |= ST_FIND_OLD;
				else
					warn( "Warning: sync record (%u,%u) has stray TUID. Ignoring.\n", srec->uid[F], srec->uid[N] );
			}
			if (srec->wstate & W_PURGE) {
				t = srec->uid[F] ? F : N;
				opts[t] |= OPEN_SETFLAGS;
			}
			if (srec->wstate & W_UPGRADE) {
				t = !srec->uid[F] ? F : N;
				opts[t] |= OPEN_APPEND;
				opts[1-t] |= OPEN_OLD;
			}
		}
	svars->opts[F] = svars->drv[F]->prepare_load_box( ctx[F], opts[F] );
	svars->opts[N] = svars->drv[N]->prepare_load_box( ctx[N], opts[N] );

	ARRAY_INIT( &mexcs );
	if (svars->opts[F] & OPEN_OLD) {
		if (chan->max_messages) {
			/* When messages have been expired on the near side, the far side fetch is split into
			 * two ranges: The bulk fetch which corresponds with the most recent messages, and an
			 * exception list of messages which would have been expired if they weren't important. */
			debug( "preparing far side selection - max expired far uid is %u\n", svars->maxxfuid );
			/* First, find out the lower bound for the bulk fetch. */
			minwuid = svars->maxxfuid + 1;
			/* Next, calculate the exception fetch. */
			for (srec = svars->srecs; srec; srec = srec->next) {
				if (srec->status & S_DEAD)
					continue;
				if (!srec->uid[F])
					continue;  // No message; other state is irrelevant
				if (srec->uid[F] >= minwuid)
					continue;  // Message is in non-expired range
				if ((svars->opts[F] & OPEN_NEW) && srec->uid[F] >= svars->maxuid[F])
					continue;  // Message is in expired range, but new range overlaps that
				if (!srec->uid[N] && !(srec->status & S_PENDING))
					continue;  // Only actually paired up messages matter
				// The pair is alive, but outside the bulk range
				*uint_array_append( &mexcs ) = srec->uid[F];
			}
			sort_uint_array( mexcs.array );
		} else {
			minwuid = 1;
		}
	} else {
		minwuid = UINT_MAX;
	}
	sync_ref( svars );
	load_box( svars, F, minwuid, mexcs.array );
	if (!check_cancel( svars ))
		load_box( svars, N, (svars->opts[N] & OPEN_OLD) ? 1 : UINT_MAX, (uint_array_t){ NULL, 0 } );
	sync_deref( svars );
}

static uint
get_seenuid( sync_vars_t *svars, int t )
{
	uint seenuid = 0;
	for (sync_rec_t *srec = svars->srecs; srec; srec = srec->next)
		if (!(srec->status & S_DEAD) && seenuid < srec->uid[t])
			seenuid = srec->uid[t];
	return seenuid;
}

static void box_loaded( int sts, message_t *msgs, int total_msgs, int recent_msgs, void *aux );

static void
load_box( sync_vars_t *svars, int t, uint minwuid, uint_array_t mexcs )
{
	uint maxwuid = 0, pairuid = UINT_MAX;

	if (svars->opts[t] & OPEN_NEW) {
		if (minwuid > svars->maxuid[t] + 1)
			minwuid = svars->maxuid[t] + 1;
		maxwuid = UINT_MAX;
		if (svars->opts[t] & OPEN_OLD_IDS)  // Implies OPEN_OLD
			pairuid = get_seenuid( svars, t );
	} else if (svars->opts[t] & OPEN_OLD) {
		maxwuid = get_seenuid( svars, t );
	}
	info( "Loading %s box...\n", str_fn[t] );
	svars->drv[t]->load_box( svars->ctx[t], minwuid, maxwuid, svars->finduid[t], pairuid, svars->maxuid[t], mexcs, box_loaded, AUX );
}

typedef struct {
	void *aux;
	sync_rec_t *srec;
	int aflags, dflags;
} flag_vars_t;

typedef struct {
	uint uid;
	sync_rec_t *srec;
} sync_rec_map_t;

static void flags_set( int sts, void *aux );
static void flags_set_p2( sync_vars_t *svars, sync_rec_t *srec, int t );
static void msgs_flags_set( sync_vars_t *svars, int t );
static void msg_copied( int sts, uint uid, copy_vars_t *vars );
static void msgs_copied( sync_vars_t *svars, int t );

static void
box_loaded( int sts, message_t *msgs, int total_msgs, int recent_msgs, void *aux )
{
	DECL_SVARS;
	sync_rec_t *srec;
	sync_rec_map_t *srecmap;
	message_t *tmsg;
	flag_vars_t *fv;
	int no[2], del[2], alive, todel;
	uchar sflags, nflags, aflags, dflags;
	uint hashsz, idx;

	if (check_ret( sts, aux ))
		return;
	INIT_SVARS(aux);
	svars->state[t] |= ST_LOADED;
	svars->msgs[t] = msgs;
	info( "%s: %d messages, %d recent\n", str_fn[t], total_msgs, recent_msgs );

	if (svars->state[t] & ST_FIND_OLD) {
		debug( "matching previously copied messages on %s\n", str_fn[t] );
		match_tuids( svars, t, msgs );
	}

	debug( "matching messages on %s against sync records\n", str_fn[t] );
	hashsz = bucketsForSize( svars->nsrecs * 3 );
	srecmap = nfcalloc( hashsz * sizeof(*srecmap) );
	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		uint uid = srec->uid[t];
		if (!uid)
			continue;
		idx = (uint)(uid * 1103515245U) % hashsz;
		while (srecmap[idx].uid)
			if (++idx == hashsz)
				idx = 0;
		srecmap[idx].uid = uid;
		srecmap[idx].srec = srec;
	}
	for (tmsg = svars->msgs[t]; tmsg; tmsg = tmsg->next) {
		if (tmsg->srec) /* found by TUID */
			continue;
		uint uid = tmsg->uid;
		idx = (uint)(uid * 1103515245U) % hashsz;
		while (srecmap[idx].uid) {
			if (srecmap[idx].uid == uid) {
				srec = srecmap[idx].srec;
				goto found;
			}
			if (++idx == hashsz)
				idx = 0;
		}
		continue;
	  found:
		tmsg->srec = srec;
		srec->msg[t] = tmsg;
	}
	free( srecmap );

	if (!(svars->state[1-t] & ST_LOADED))
		return;

	for (t = 0; t < 2; t++) {
		if (svars->uidval[t] != UIDVAL_BAD && svars->uidval[t] != svars->newuidval[t]) {
			// This code checks whether the messages with known UIDs are actually the
			// same messages, as recognized by their Message-IDs.
			unsigned need = 0, got = 0;
			debug( "trying to re-approve uid validity of %s\n", str_fn[t] );
			for (srec = svars->srecs; srec; srec = srec->next) {
				if (srec->status & S_DEAD)
					continue;
				need++;
				if (!srec->msg[t])
					continue;  // Message disappeared.
				// Present paired messages require re-validation.
				if (!srec->msg[t]->msgid)
					continue;  // Messages without ID are useless for re-validation.
				if (!srec->msg[1-t])
					continue;  // Partner disappeared.
				if (!srec->msg[1-t]->msgid || strcmp( srec->msg[F]->msgid, srec->msg[N]->msgid )) {
					error( "Error: channel %s, %s box %s: UIDVALIDITY genuinely changed (at UID %u).\n",
					       svars->chan->name, str_fn[t], svars->orig_name[t], srec->uid[t] );
				  uvchg:
					svars->ret |= SYNC_FAIL;
					cancel_sync( svars );
					return;
				}
				got++;
			}
			// We encountered no messages that contradict the hypothesis that the
			// UIDVALIDITY change was spurious.
			// If we got enough messages confirming the hypothesis, we just accept it.
			// If there aren't quite enough messages, we check that at least 80% of
			// those previously present are still there and confirm the hypothesis;
			// this also covers the case of a box that was already empty.
			if (got < 20 && got * 5 < need * 4) {
				// Too few confirmed messages. This is very likely in the drafts folder.
				// A proper fallback would be fetching more headers (which potentially need
				// normalization) or the message body (which should be truncated for sanity)
				// and comparing.
				error( "Error: channel %s, %s box %s: Unable to recover from UIDVALIDITY change.\n",
				       svars->chan->name, str_fn[t], svars->orig_name[t] );
				goto uvchg;
			}
			notice( "Notice: channel %s, %s box %s: Recovered from change of UIDVALIDITY.\n",
			        svars->chan->name, str_fn[t], svars->orig_name[t] );
			svars->uidval[t] = UIDVAL_BAD;
		}
	}

	if (svars->uidval[F] == UIDVAL_BAD || svars->uidval[N] == UIDVAL_BAD) {
		svars->uidval[F] = svars->newuidval[F];
		svars->uidval[N] = svars->newuidval[N];
		JLOG( "| %u %u", (svars->uidval[F], svars->uidval[N]), "new UIDVALIDITYs" );
	}

	svars->oldmaxuid[F] = svars->maxuid[F];
	svars->oldmaxuid[N] = svars->maxuid[N];
	svars->oldmaxxfuid = svars->maxxfuid;

	info( "Synchronizing...\n" );
	for (t = 0; t < 2; t++)
		svars->good_flags[t] = (uchar)svars->drv[t]->get_supported_flags( svars->ctx[t] );

	int any_new[2] = { 0, 0 };

	debug( "synchronizing old entries\n" );
	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		debug( "pair (%u,%u)\n", srec->uid[F], srec->uid[N] );
		assert( !srec->tuid[0] );
		// no[] means that a message is known to be not there.
		no[F] = !srec->msg[F] && (svars->opts[F] & OPEN_OLD);
		no[N] = !srec->msg[N] && (svars->opts[N] & OPEN_OLD);
		if (no[F] && no[N]) {
			// It does not matter whether one side was already known to be missing
			// (never stored [skipped or failed] or expunged [possibly expired]) -
			// now both are missing, so the entry is superfluous.
			srec->status = S_DEAD;
			JLOG( "- %u %u", (srec->uid[F], srec->uid[N]), "both missing" );
		} else {
			// del[] means that a message becomes known to have been expunged.
			del[F] = no[F] && srec->uid[F];
			del[N] = no[N] && srec->uid[N];

			for (t = 0; t < 2; t++) {
				if (srec->msg[t] && (srec->msg[t]->flags & F_DELETED))
					srec->wstate |= W_DEL(t);
				if (del[t]) {
					// The target was newly expunged, so there is nothing to update.
					// The deletion is propagated in the opposite iteration.
				} else if (!srec->uid[t]) {
					// The target was never stored, or was previously expunged, so there
					// is nothing to update.
					// Note: the opposite UID must be valid, as otherwise the entry would
					// have been pruned already.
				} else if (del[1-t]) {
					// The source was newly expunged, so possibly propagate the deletion.
					// The target may be in an unknown state (not fetched).
					if ((t == F) && (srec->status & (S_EXPIRE|S_EXPIRED))) {
						/* Don't propagate deletion resulting from expiration. */
						JLOG( "> %u %u 0", (srec->uid[F], srec->uid[N]), "near side expired, orphaning far side" );
						srec->uid[N] = 0;
					} else {
						if (srec->msg[t] && (srec->msg[t]->status & M_FLAGS) &&
						    // Ignore deleted flag, as that's what we'll change ourselves ...
						    (((srec->msg[t]->flags & ~F_DELETED) != (srec->flags & ~F_DELETED)) ||
						     // ... except for undeletion, as that's the opposite.
						     (!(srec->msg[t]->flags & F_DELETED) && (srec->flags & F_DELETED))))
							notice( "Notice: conflicting changes in (%u,%u)\n", srec->uid[F], srec->uid[N] );
						if (svars->chan->ops[t] & OP_DELETE) {
							debug( "  %sing delete\n", str_hl[t] );
							srec->aflags[t] = F_DELETED;
							srec->wstate |= W_DELETE;
						} else {
							debug( "  not %sing delete\n", str_hl[t] );
						}
					}
				} else if (!srec->msg[1-t]) {
					// We have no source to work with, because it was never stored,
					// it was previously expunged, or we did not fetch it.
					debug( "  no %s\n", str_fn[1-t] );
				} else {
					// We have a source. The target may be in an unknown state.
					if (svars->chan->ops[t] & OP_FLAGS) {
						sflags = sanitize_flags( srec->msg[1-t]->flags, svars, t );
						if ((t == F) && (srec->status & (S_EXPIRE|S_EXPIRED))) {
							/* Don't propagate deletion resulting from expiration. */
							debug( "  near side expiring\n" );
							sflags &= ~F_DELETED;
						}
						if (srec->status & S_DUMMY(1-t)) {
							// For placeholders, don't propagate:
							// - Seen, because the real contents were obviously not seen yet
							// - Flagged, because it's just a request to upgrade
							sflags &= ~(F_SEEN|F_FLAGGED);
						}
						srec->aflags[t] = sflags & ~srec->flags;
						srec->dflags[t] = ~sflags & srec->flags;
						if ((DFlags & DEBUG_SYNC) && (srec->aflags[t] || srec->dflags[t])) {
							char afbuf[16], dfbuf[16]; /* enlarge when support for keywords is added */
							make_flags( srec->aflags[t], afbuf );
							make_flags( srec->dflags[t], dfbuf );
							debug( "  %sing flags: +%s -%s\n", str_hl[t], afbuf, dfbuf );
						}
					}
				}
			}

			sync_rec_t *nsrec = srec;
			if (((srec->status & S_DUMMY(F)) && (svars->chan->ops[F] & OP_RENEW)) ||
			     ((srec->status & S_DUMMY(N)) && (svars->chan->ops[N] & OP_RENEW))) {
				// Flagging the message on either side causes an upgrade of the dummy.
				// We ignore flag resets, because that corner case is not worth it.
				ushort muflags = srec->msg[F] ? srec->msg[F]->flags : 0;
				ushort suflags = srec->msg[N] ? srec->msg[N]->flags : 0;
				if ((muflags | suflags) & F_FLAGGED) {
					t = (srec->status & S_DUMMY(F)) ? F : N;
					// We calculate the flags for the replicated message already now,
					// because after an interruption the dummy may be already gone.
					srec->pflags = ((srec->msg[t]->flags & ~(F_SEEN|F_FLAGGED)) | srec->aflags[t]) & ~srec->dflags[t];
					// Consequently, the srec's flags are committed right away as well.
					srec->flags = (srec->flags | srec->aflags[t]) & ~srec->dflags[t];
					JLOG( "^ %u %u %u %u", (srec->uid[F], srec->uid[N], srec->pflags, srec->flags), "upgrading placeholder" );
					nsrec = upgrade_srec( svars, srec );
				}
			}
			// This is separated, because the upgrade can come from the journal.
			if (srec->wstate & W_UPGRADE) {
				t = !srec->uid[F] ? F : N;
				tmsg = srec->msg[1-t];
				if ((svars->chan->ops[t] & OP_EXPUNGE) && (srec->pflags & F_DELETED)) {
					JLOG( "- %u %u", (srec->uid[F], srec->uid[N]), "killing upgrade - would be expunged anyway" );
					tmsg->srec = NULL;
					srec->status = S_DEAD;
				} else {
					// Pretend that the source message has the adjusted flags of the dummy.
					tmsg->flags = srec->pflags;
					tmsg->status = M_FLAGS;
					any_new[t] = 1;
				}
			}
			srec = nsrec;
		}
	}

	for (t = 0; t < 2; t++) {
		debug( "synchronizing new messages on %s\n", str_fn[1-t] );
		for (tmsg = svars->msgs[1-t]; tmsg; tmsg = tmsg->next) {
			srec = tmsg->srec;
			if (srec) {
				if (srec->status & S_SKIPPED) {
					// Pre-1.4 legacy only: The message was skipped due to being too big.
					// We must have already seen the UID, but we might have been interrupted.
					if (svars->maxuid[1-t] < tmsg->uid)
						svars->maxuid[1-t] = tmsg->uid;
					if (!(svars->chan->ops[t] & OP_RENEW))
						continue;
					srec->status = S_PENDING;
					// The message size was not queried, so this won't be dummified below.
					if (!(tmsg->flags & F_FLAGGED)) {
						srec->status |= S_DUMMY(t);
						JLOG( "_ %u %u", (srec->uid[F], srec->uid[N]), "placeholder only - was previously skipped" );
					} else {
						JLOG( "~ %u %u %u", (srec->uid[F], srec->uid[N], srec->status), "was previously skipped" );
					}
				} else {
					if (!(svars->chan->ops[t] & OP_NEW))
						continue;
					// This catches messages:
					// - that are actually new
					// - whose propagation got interrupted
					// - whose propagation was completed, but not logged yet
					// - that aren't actually new, but a result of syncing, and the instant
					//   maxuid upping was prevented by the presence of actually new messages
					if (svars->maxuid[1-t] < tmsg->uid)
						svars->maxuid[1-t] = tmsg->uid;
					if (!(srec->status & S_PENDING))
						continue;  // Nothing to do - the message is paired or expired
					// Propagation was scheduled, but we got interrupted
					debug( "unpropagated old message %u\n", tmsg->uid );
				}

				if ((svars->chan->ops[t] & OP_EXPUNGE) && (tmsg->flags & F_DELETED)) {
					JLOG( "- %u %u", (srec->uid[F], srec->uid[N]), "killing - would be expunged anyway" );
					tmsg->srec = NULL;
					srec->status = S_DEAD;
					continue;
				}
			} else {
				if (!(svars->chan->ops[t] & OP_NEW))
					continue;
				if (tmsg->uid <= svars->maxuid[1-t]) {
					// The message should be already paired. It's not, so it was:
					// - previously paired, but the entry was expired and pruned => ignore
					// - attempted, but failed => ignore (the wisdom of this is debatable)
					// - ignored, as it would have been expunged anyway => ignore (even if undeleted)
					continue;
				}
				svars->maxuid[1-t] = tmsg->uid;
				debug( "new message %u\n", tmsg->uid );

				if ((svars->chan->ops[t] & OP_EXPUNGE) && (tmsg->flags & F_DELETED)) {
					debug( "-> ignoring - would be expunged anyway\n" );
					continue;
				}

				srec = nfcalloc( sizeof(*srec) );
				*svars->srecadd = srec;
				svars->srecadd = &srec->next;
				svars->nsrecs++;
				srec->status = S_PENDING;
				srec->uid[1-t] = tmsg->uid;
				srec->msg[1-t] = tmsg;
				tmsg->srec = srec;
				JLOG( "+ %u %u", (srec->uid[F], srec->uid[N]), "fresh" );
			}
			if (!(tmsg->flags & F_FLAGGED) && tmsg->size > svars->chan->stores[t]->max_size &&
			    !(srec->wstate & W_UPGRADE) && !(srec->status & (S_DUMMY(F)|S_DUMMY(N)))) {
				srec->status |= S_DUMMY(t);
				JLOG( "_ %u %u", (srec->uid[F], srec->uid[N]), "placeholder only - too big" );
			}
			any_new[t] = 1;
		}
	}

	if ((svars->chan->ops[N] & (OP_NEW|OP_RENEW|OP_FLAGS)) && svars->chan->max_messages) {
		// Note: When this branch is entered, we have loaded all near side messages.
		/* Expire excess messages. Important (flagged, unread, or unpropagated) messages
		 * older than the first not expired message are not counted towards the total. */
		debug( "preparing message expiration\n" );
		// Due to looping only over the far side, we completely ignore unpaired
		// near-side messages. This is correct, as we cannot expire them without
		// data loss anyway; consequently, we also don't count them.
		// Note that we also ignore near-side messages we're currently propagating,
		// which delays expiration of some messages by one cycle. Otherwise, we'd have
		// to sequence flag propagation after message propagation to avoid a race
		// with 3rd-party expunging, and that seems unreasonably expensive.
		alive = 0;
		for (tmsg = svars->msgs[F]; tmsg; tmsg = tmsg->next) {
			if (tmsg->status & M_DEAD)
				continue;
			// We ignore unpaired far-side messages, as there is obviously nothing
			// to expire in the first place.
			if (!(srec = tmsg->srec))
				continue;
			if (!(srec->status & S_PENDING)) {
				if (!srec->msg[N])
					continue;  // Already expired or skipped.
				nflags = (srec->msg[N]->flags | srec->aflags[N]) & ~srec->dflags[N];
			} else {
				nflags = tmsg->flags;
			}
			if (!(nflags & F_DELETED) || (srec->status & (S_EXPIRE|S_EXPIRED)))
				// The message is not deleted, or it is, but only due to being expired.
				alive++;
		}
		todel = alive - svars->chan->max_messages;
		debug( "%d alive messages, %d excess - expiring\n", alive, todel );
		alive = 0;
		for (tmsg = svars->msgs[F]; tmsg; tmsg = tmsg->next) {
			if (tmsg->status & M_DEAD)
				continue;
			if (!(srec = tmsg->srec))
				continue;
			if (!(srec->status & S_PENDING)) {
				if (!srec->msg[N])
					continue;
				nflags = (srec->msg[N]->flags | srec->aflags[N]) & ~srec->dflags[N];
			} else {
				nflags = tmsg->flags;
			}
			if (!(nflags & F_DELETED) || (srec->status & (S_EXPIRE|S_EXPIRED))) {
				if ((nflags & F_FLAGGED) ||
				    !((nflags & F_SEEN) || ((void)(todel > 0 && alive++), svars->chan->expire_unread > 0))) {
					// Important messages are always fetched/kept.
					debug( "  pair(%u,%u) is important\n", srec->uid[F], srec->uid[N] );
					todel--;
				} else if (todel > 0 ||
				           ((srec->status & (S_EXPIRE|S_EXPIRED)) == (S_EXPIRE|S_EXPIRED)) ||
				           ((srec->status & (S_EXPIRE|S_EXPIRED)) && (srec->msg[N]->flags & F_DELETED))) {
					/* The message is excess or was already (being) expired. */
					srec->wstate |= W_NEXPIRE;
					debug( "  pair(%u,%u) expired\n", srec->uid[F], srec->uid[N] );
					if (svars->maxxfuid < srec->uid[F])
						svars->maxxfuid = srec->uid[F];
					todel--;
				}
			}
		}
		debug( "%d excess messages remain\n", todel );
		if (svars->chan->expire_unread < 0 && alive * 2 > svars->chan->max_messages) {
			error( "%s: %d unread messages in excess of MaxMessages (%d).\n"
			       "Please set ExpireUnread to decide outcome. Skipping mailbox.\n",
			       svars->orig_name[N], alive, svars->chan->max_messages );
			svars->ret |= SYNC_FAIL;
			cancel_sync( svars );
			return;
		}
		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (!(srec->status & S_PENDING)) {
				if (!srec->msg[N])
					continue;
				uchar nex = (srec->wstate / W_NEXPIRE) & 1;
				if (nex != ((srec->status / S_EXPIRED) & 1)) {
					/* The record needs a state change ... */
					if (nex != ((srec->status / S_EXPIRE) & 1)) {
						/* ... and we need to start a transaction. */
						srec->status = (srec->status & ~S_EXPIRE) | (nex * S_EXPIRE);
						JLOG( "~ %u %u %u", (srec->uid[F], srec->uid[N], srec->status), "expire %u - begin", nex );
					} else {
						/* ... but the "right" transaction is already pending. */
						debug( "-> pair(%u,%u): expire %u (pending)\n", srec->uid[F], srec->uid[N], nex );
					}
				} else {
					/* Note: the "wrong" transaction may be pending here,
					 * e.g.: W_NEXPIRE = 0, S_EXPIRE = 1, S_EXPIRED = 0. */
				}
			} else {
				if (srec->wstate & W_NEXPIRE) {
					JLOG( "= %u %u", (srec->uid[F], srec->uid[N]), "expire unborn" );
					// If we have so many new messages that some of them are instantly expired,
					// but some are still propagated because they are important, we need to
					// ensure explicitly that the bulk fetch limit is upped.
					if (svars->maxxfuid < srec->uid[F])
						svars->maxxfuid = srec->uid[F];
					srec->msg[F]->srec = NULL;
					srec->status = S_DEAD;
				}
			}
		}
	}

	sync_ref( svars );

	debug( "synchronizing flags\n" );
	for (srec = svars->srecs; srec; srec = srec->next) {
		if (srec->status & S_DEAD)
			continue;
		for (t = 0; t < 2; t++) {
			if (!srec->uid[t])
				continue;
			aflags = srec->aflags[t];
			dflags = srec->dflags[t];
			if (srec->wstate & (W_DELETE|W_PURGE)) {
				if (!aflags) {
					// This deletion propagation goes the other way round, or
					// this deletion of a dummy happens on the other side.
					continue;
				}
				if (!srec->msg[t] && (svars->opts[t] & OPEN_OLD)) {
					// The message disappeared. This can happen, because the wstate may
					// come from the journal, and things could have happened meanwhile.
					continue;
				}
			} else {
				/* The trigger is an expiration transaction being ongoing ... */
				if ((t == N) && ((shifted_bit(srec->status, S_EXPIRE, S_EXPIRED) ^ srec->status) & S_EXPIRED)) {
					/* ... but the actual action derives from the wanted state. */
					if (srec->wstate & W_NEXPIRE)
						aflags |= F_DELETED;
					else
						dflags |= F_DELETED;
				}
			}
			if ((svars->chan->ops[t] & OP_EXPUNGE) && (((srec->msg[t] ? srec->msg[t]->flags : 0) | aflags) & ~dflags & F_DELETED) &&
			    (!svars->ctx[t]->conf->trash || svars->ctx[t]->conf->trash_only_new))
			{
				/* If the message is going to be expunged, don't propagate anything but the deletion. */
				srec->aflags[t] &= F_DELETED;
				aflags &= F_DELETED;
				srec->dflags[t] = dflags = 0;
			}
			if (srec->msg[t] && (srec->msg[t]->status & M_FLAGS)) {
				/* If we know the target message's state, optimize away non-changes. */
				aflags &= ~srec->msg[t]->flags;
				dflags &= srec->msg[t]->flags;
			}
			if (aflags | dflags) {
				flags_total[t]++;
				stats();
				svars->flags_pending[t]++;
				fv = nfmalloc( sizeof(*fv) );
				fv->aux = AUX;
				fv->srec = srec;
				fv->aflags = aflags;
				fv->dflags = dflags;
				svars->drv[t]->set_msg_flags( svars->ctx[t], srec->msg[t], srec->uid[t], aflags, dflags, flags_set, fv );
				if (check_cancel( svars ))
					goto out;
			} else
				flags_set_p2( svars, srec, t );
		}
	}
	for (t = 0; t < 2; t++) {
		svars->drv[t]->commit_cmds( svars->ctx[t] );
		svars->state[t] |= ST_SENT_FLAGS;
		msgs_flags_set( svars, t );
		if (check_cancel( svars ))
			goto out;
	}

	debug( "propagating new messages\n" );
	if (UseFSync && svars->jfp)
		fdatasync( fileno( svars->jfp ) );
	for (t = 0; t < 2; t++) {
		if (any_new[t]) {
			svars->finduid[t] = svars->drv[t]->get_uidnext( svars->ctx[t] );
			JLOG( "F %d %u", (t, svars->finduid[t]), "save UIDNEXT of %s", str_fn[t] );
			svars->new_msgs[t] = svars->msgs[1-t];
		} else {
			svars->state[t] |= ST_SENT_NEW;
		}
		msgs_copied( svars, t );
		if (check_cancel( svars ))
			goto out;
	}

  out:
	sync_deref( svars );
}

static void
msg_copied( int sts, uint uid, copy_vars_t *vars )
{
	SVARS_CHECK_CANCEL_RET;
	sync_rec_t *srec = vars->srec;
	switch (sts) {
	case SYNC_OK:
		if (!(srec->wstate & W_UPGRADE) && vars->msg->flags != srec->flags) {
			srec->flags = vars->msg->flags;
			JLOG( "* %u %u %u", (srec->uid[F], srec->uid[N], srec->flags), "%sed with flags", str_hl[t] );
		}
		if (!uid) {  // Stored to a non-UIDPLUS mailbox
			svars->state[t] |= ST_FIND_NEW;
		} else {
			ASSIGN_UID( srec, t, uid, "%sed message", str_hl[t] );
		}
		break;
	case SYNC_NOGOOD:
		srec->status = S_DEAD;
		JLOG( "- %u %u", (srec->uid[F], srec->uid[N]), "%s failed", str_hl[t] );
		break;
	default:
		cancel_sync( svars );
		free( vars );
		return;
	}
	free( vars );
	new_done[t]++;
	stats();
	svars->new_pending[t]--;
	msgs_copied( svars, t );
}

static void msgs_found_new( int sts, message_t *msgs, void *aux );
static void msgs_new_done( sync_vars_t *svars, int t );
static void sync_close( sync_vars_t *svars, int t );

static void
msgs_copied( sync_vars_t *svars, int t )
{
	message_t *tmsg;
	sync_rec_t *srec;
	copy_vars_t *cv;

	if (svars->state[t] & ST_SENDING_NEW)
		return;

	sync_ref( svars );

	if (!(svars->state[t] & ST_SENT_NEW)) {
		for (tmsg = svars->new_msgs[t]; tmsg; tmsg = tmsg->next) {
			if ((srec = tmsg->srec) && (srec->status & S_PENDING)) {
				if (svars->drv[t]->get_memory_usage( svars->ctx[t] ) >= BufferLimit) {
					svars->new_msgs[t] = tmsg;
					goto out;
				}
				for (uint i = 0; i < TUIDL; i++) {
					uchar c = arc4_getbyte() & 0x3f;
					srec->tuid[i] = (char)(c < 26 ? c + 'A' : c < 52 ? c + 'a' - 26 : c < 62 ? c + '0' - 52 : c == 62 ? '+' : '/');
				}
				JLOG( "# %u %u %." stringify(TUIDL) "s", (srec->uid[F], srec->uid[N], srec->tuid), "%sing message", str_hl[t] );
				new_total[t]++;
				stats();
				svars->new_pending[t]++;
				svars->state[t] |= ST_SENDING_NEW;
				cv = nfmalloc( sizeof(*cv) );
				cv->cb = msg_copied;
				cv->aux = AUX;
				cv->srec = srec;
				cv->msg = tmsg;
				cv->minimal = (srec->status & S_DUMMY(t));
				copy_msg( cv );
				svars->state[t] &= ~ST_SENDING_NEW;
				if (check_cancel( svars ))
					goto out;
			}
		}
		svars->state[t] |= ST_SENT_NEW;
	}

	if (svars->new_pending[t])
		goto out;

	sync_close( svars, 1-t );
	if (check_cancel( svars ))
		goto out;

	if (svars->state[t] & ST_FIND_NEW) {
		debug( "finding just copied messages on %s\n", str_fn[t] );
		svars->drv[t]->find_new_msgs( svars->ctx[t], svars->finduid[t], msgs_found_new, AUX );
	} else {
		msgs_new_done( svars, t );
	}

  out:
	sync_deref( svars );
}

static void
msgs_found_new( int sts, message_t *msgs, void *aux )
{
	SVARS_CHECK_RET;
	switch (sts) {
	case DRV_OK:
		debug( "matching just copied messages on %s\n", str_fn[t] );
		break;
	default:
		warn( "Warning: cannot find newly stored messages on %s.\n", str_fn[t] );
		break;
	}
	match_tuids( svars, t, msgs );
	msgs_new_done( svars, t );
}

static void
msgs_new_done( sync_vars_t *svars, int t )
{
	svars->state[t] |= ST_FOUND_NEW;
	sync_close( svars, t );
}

static void
flags_set( int sts, void *aux )
{
	SVARS_CHECK_RET_VARS(flag_vars_t);
	sync_rec_t *srec = vars->srec;
	switch (sts) {
	case DRV_OK:
		if (vars->aflags & F_DELETED)
			srec->wstate |= W_DEL(t);
		else if (vars->dflags & F_DELETED)
			srec->wstate &= ~W_DEL(t);
		flags_set_p2( svars, srec, t );
		break;
	}
	free( vars );
	flags_done[t]++;
	stats();
	svars->flags_pending[t]--;
	msgs_flags_set( svars, t );
}

static void
flags_set_p2( sync_vars_t *svars, sync_rec_t *srec, int t )
{
	if (srec->wstate & W_DELETE) {
		JLOG( "%c %u %u 0", ("><"[t], srec->uid[F], srec->uid[N]), "%sed deletion", str_hl[t] );
		srec->uid[1-t] = 0;
	} else {
		uchar nflags = (srec->flags | srec->aflags[t]) & ~srec->dflags[t];
		if (srec->flags != nflags) {
			JLOG( "* %u %u %u", (srec->uid[F], srec->uid[N], nflags), "%sed flags; were %u", (str_hl[t], srec->flags) );
			srec->flags = nflags;
		}
		if (t == N) {
			uchar nex = (srec->wstate / W_NEXPIRE) & 1;
			if (nex != ((srec->status / S_EXPIRED) & 1)) {
				srec->status = (srec->status & ~S_EXPIRED) | (nex * S_EXPIRED);
				JLOG( "~ %u %u %u", (srec->uid[F], srec->uid[N], srec->status), "expired %d - commit", nex );
			} else if (nex != ((srec->status / S_EXPIRE) & 1)) {
				srec->status = (srec->status & ~S_EXPIRE) | (nex * S_EXPIRE);
				JLOG( "~ %u %u %u", (srec->uid[F], srec->uid[N], srec->status), "expire %d - cancel", nex );
			}
		}
	}
}

typedef struct {
	void *aux;
	message_t *msg;
} trash_vars_t;

static void msg_trashed( int sts, void *aux );
static void msg_rtrashed( int sts, uint uid, copy_vars_t *vars );

static void
msgs_flags_set( sync_vars_t *svars, int t )
{
	message_t *tmsg;
	trash_vars_t *tv;
	copy_vars_t *cv;

	if (!(svars->state[t] & ST_SENT_FLAGS) || svars->flags_pending[t])
		return;

	sync_ref( svars );

	if ((svars->chan->ops[t] & OP_EXPUNGE) &&
	    (svars->ctx[t]->conf->trash || (svars->ctx[1-t]->conf->trash && svars->ctx[1-t]->conf->trash_remote_new))) {
		debug( "trashing on %s\n", str_fn[t] );
		for (tmsg = svars->msgs[t]; tmsg; tmsg = tmsg->next)
			if ((tmsg->flags & F_DELETED) && !find_uint_array( svars->trashed_msgs[t].array, tmsg->uid ) &&
			    (t == F || !tmsg->srec || !(tmsg->srec->status & (S_EXPIRE|S_EXPIRED)))) {
				if (svars->ctx[t]->conf->trash) {
					if (!svars->ctx[t]->conf->trash_only_new || !tmsg->srec || (tmsg->srec->status & (S_PENDING | S_SKIPPED))) {
						debug( "%s: trashing message %u\n", str_fn[t], tmsg->uid );
						trash_total[t]++;
						stats();
						svars->trash_pending[t]++;
						tv = nfmalloc( sizeof(*tv) );
						tv->aux = AUX;
						tv->msg = tmsg;
						svars->drv[t]->trash_msg( svars->ctx[t], tmsg, msg_trashed, tv );
						if (check_cancel( svars ))
							goto out;
					} else
						debug( "%s: not trashing message %u - not new\n", str_fn[t], tmsg->uid );
				} else {
					if (!tmsg->srec || (tmsg->srec->status & (S_PENDING | S_SKIPPED))) {
						if (tmsg->size <= svars->ctx[1-t]->conf->max_size) {
							debug( "%s: remote trashing message %u\n", str_fn[t], tmsg->uid );
							trash_total[t]++;
							stats();
							svars->trash_pending[t]++;
							cv = nfmalloc( sizeof(*cv) );
							cv->cb = msg_rtrashed;
							cv->aux = INV_AUX;
							cv->srec = NULL;
							cv->msg = tmsg;
							cv->minimal = 0;
							copy_msg( cv );
							if (check_cancel( svars ))
								goto out;
						} else
							debug( "%s: not remote trashing message %u - too big\n", str_fn[t], tmsg->uid );
					} else
						debug( "%s: not remote trashing message %u - not new\n", str_fn[t], tmsg->uid );
				}
			}
	}
	svars->state[t] |= ST_SENT_TRASH;
	sync_close( svars, t );

  out:
	sync_deref( svars );
}

static void
msg_trashed( int sts, void *aux )
{
	trash_vars_t *vars = (trash_vars_t *)aux;
	DECL_SVARS;

	if (sts == DRV_MSG_BAD)
		sts = DRV_BOX_BAD;
	if (check_ret( sts, vars->aux ))
		return;
	INIT_SVARS(vars->aux);
	JLOG( "T %d %u", (t, vars->msg->uid), "trashed on %s", str_fn[t] );
	free( vars );
	trash_done[t]++;
	stats();
	svars->trash_pending[t]--;
	sync_close( svars, t );
}

static void
msg_rtrashed( int sts, uint uid ATTR_UNUSED, copy_vars_t *vars )
{
	SVARS_CHECK_CANCEL_RET;
	switch (sts) {
	case SYNC_OK:
	case SYNC_NOGOOD: /* the message is gone or heavily busted */
		break;
	default:
		cancel_sync( svars );
		free( vars );
		return;
	}
	t ^= 1;
	JLOG( "T %d %u", (t, vars->msg->uid), "trashed remotely on %s", str_fn[1-t] );
	free( vars );
	trash_done[t]++;
	stats();
	svars->trash_pending[t]--;
	sync_close( svars, t );
}

static void box_closed( int sts, void *aux );
static void box_closed_p2( sync_vars_t *svars, int t );

static void
sync_close( sync_vars_t *svars, int t )
{
	if ((~svars->state[t] & (ST_FOUND_NEW|ST_SENT_TRASH)) || svars->trash_pending[t] ||
	    !(svars->state[1-t] & ST_SENT_NEW) || svars->new_pending[1-t])
		return;

	if (svars->state[t] & ST_CLOSING)
		return;
	svars->state[t] |= ST_CLOSING;

	if ((svars->chan->ops[t] & OP_EXPUNGE) /*&& !(svars->state[t] & ST_TRASH_BAD)*/) {
		debug( "expunging %s\n", str_fn[t] );
		svars->drv[t]->close_box( svars->ctx[t], box_closed, AUX );
	} else {
		box_closed_p2( svars, t );
	}
}

static void
box_closed( int sts, void *aux )
{
	SVARS_CHECK_RET;
	svars->state[t] |= ST_DID_EXPUNGE;
	box_closed_p2( svars, t );
}

static void
box_closed_p2( sync_vars_t *svars, int t )
{
	sync_rec_t *srec;

	svars->state[t] |= ST_CLOSED;
	if (!(svars->state[1-t] & ST_CLOSED))
		return;

	// All the journalling done in this function is merely for the autotest -
	// the operations are idempotent, and we're about to commit the new state
	// right afterwards anyway.

	for (t = 0; t < 2; t++) {
		// Committing maxuid is delayed until all messages were propagated, to
		// ensure that all pending messages are still loaded next time in case
		// of interruption - in particular skipping big messages would otherwise
		// up the limit too early.
		if (svars->maxuid[t] != svars->oldmaxuid[t])
			JLOG( "N %d %u", (t, svars->maxuid[t]), "up maxuid of %s", str_fn[t] );
	}

	if (((svars->state[F] | svars->state[N]) & ST_DID_EXPUNGE) || svars->chan->max_messages) {
		debug( "purging obsolete entries\n" );
		for (srec = svars->srecs; srec; srec = srec->next) {
			if (srec->status & S_DEAD)
				continue;
			if (!srec->uid[N] || ((srec->wstate & W_DEL(N)) && (svars->state[N] & ST_DID_EXPUNGE))) {
				if (!srec->uid[F] || ((srec->wstate & W_DEL(F)) && (svars->state[F] & ST_DID_EXPUNGE)) ||
				    ((srec->status & S_EXPIRED) && svars->maxuid[F] >= srec->uid[F] && svars->maxxfuid >= srec->uid[F])) {
					JLOG( "- %u %u", (srec->uid[F], srec->uid[N]), "killing" );
					srec->status = S_DEAD;
				} else if (srec->uid[N]) {
					JLOG( "> %u %u 0", (srec->uid[F], srec->uid[N]), "orphaning" );
					srec->uid[N] = 0;
				}
			} else if (srec->uid[F] && ((srec->wstate & W_DEL(F)) && (svars->state[F] & ST_DID_EXPUNGE))) {
				JLOG( "< %u %u 0", (srec->uid[F], srec->uid[N]), "orphaning" );
				srec->uid[F] = 0;
			}
		}
	}

	// This is just an optimization, so it needs no journaling of intermediate states.
	// However, doing it before the entry purge would require ensuring that the
	// exception list includes all relevant messages.
	if (svars->maxxfuid != svars->oldmaxxfuid)
		JLOG( "! %u", svars->maxxfuid, "max expired UID on far side" );

	save_state( svars );

	sync_bail( svars );
}

static void
sync_bail( sync_vars_t *svars )
{
	sync_rec_t *srec, *nsrec;

	free( svars->trashed_msgs[F].array.data );
	free( svars->trashed_msgs[N].array.data );
	for (srec = svars->srecs; srec; srec = nsrec) {
		nsrec = srec->next;
		free( srec );
	}
	if (svars->lfd >= 0) {
		unlink( svars->lname );
		close( svars->lfd );
	}
	sync_bail2( svars );
}

static void
sync_bail2( sync_vars_t *svars )
{
	free( svars->lname );
	free( svars->nname );
	free( svars->jname );
	free( svars->dname );
	sync_bail3( svars );
}

static void
sync_bail3( sync_vars_t *svars )
{
	free( svars->box_name[F] );
	free( svars->box_name[N] );
	sync_deref( svars );
}

static void
sync_deref( sync_vars_t *svars )
{
	if (!--svars->ref_count) {
		void (*cb)( int sts, void *aux ) = svars->cb;
		void *aux = svars->aux;
		int ret = svars->ret;
		free( svars );
		cb( ret, aux );
	}
}
