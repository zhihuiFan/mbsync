/*
 * mbsync - mailbox synchronizer
 * Copyright (C) 2017 Oswald Buddenhagen <ossi@users.sf.net>
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

#include "driver.h"

#include <assert.h>
#include <limits.h>
#include <stdlib.h>

typedef struct gen_cmd gen_cmd_t;

typedef union proxy_store {
	store_t gen;
	struct {
		STORE(union proxy_store)
		const char *label;  // foreign
		uint ref_count;
		driver_t *real_driver;
		store_t *real_store;
		gen_cmd_t *done_cmds, **done_cmds_append;
		gen_cmd_t *check_cmds, **check_cmds_append;
		wakeup_t wakeup;

		void (*bad_callback)( void *aux );
		void *bad_callback_aux;
	};
} proxy_store_t;

static void ATTR_PRINTFLIKE(1, 2)
debug( const char *msg, ... )
{
	va_list va;

	va_start( va, msg );
	vdebug( DEBUG_DRV, msg, va );
	va_end( va );
}

static void ATTR_PRINTFLIKE(1, 2)
debugn( const char *msg, ... )
{
	va_list va;

	va_start( va, msg );
	vdebugn( DEBUG_DRV, msg, va );
	va_end( va );
}

/* Keep the mailbox driver flag definitions in sync: */
/* grep for MAILBOX_DRIVER_FLAG */
/* The order is according to alphabetical maildir flag sort */
static const char Flags[] = { 'D', 'F', 'P', 'R', 'S', 'T' };

static char *
proxy_make_flags( uchar flags, char *buf )
{
	uint i, d;

	for (d = 0, i = 0; i < as(Flags); i++)
		if (flags & (1 << i))
			buf[d++] = Flags[i];
	buf[d] = 0;
	return buf;
}

static void
proxy_store_deref( proxy_store_t *ctx )
{
	if (!--ctx->ref_count) {
		assert( !pending_wakeup( &ctx->wakeup ) );
		free( ctx );
	}
}

static int curr_tag;

#define GEN_CMD \
	uint ref_count; \
	int tag; \
	proxy_store_t *ctx; \
	gen_cmd_t *next; \
	void (*queued_cb)( gen_cmd_t *gcmd );

struct gen_cmd {
	GEN_CMD
};

#define GEN_STS_CMD \
	GEN_CMD \
	int sts;

typedef union {
	gen_cmd_t gen;
	struct {
		GEN_STS_CMD
	};
} gen_sts_cmd_t;

static gen_cmd_t *
proxy_cmd_new( proxy_store_t *ctx, uint sz )
{
	gen_cmd_t *cmd = nfmalloc( sz );
	cmd->ref_count = 2;
	cmd->tag = ++curr_tag;
	cmd->ctx = ctx;
	ctx->ref_count++;
	return cmd;
}

static void
proxy_cmd_done( gen_cmd_t *cmd )
{
	if (!--cmd->ref_count) {
		proxy_store_deref( cmd->ctx );
		free( cmd );
	}
}

static void
proxy_wakeup( void *aux )
{
	proxy_store_t *ctx = (proxy_store_t *)aux;

	gen_cmd_t *cmd = ctx->done_cmds;
	assert( cmd );
	if (!(ctx->done_cmds = cmd->next))
		ctx->done_cmds_append = &ctx->done_cmds;
	else
		conf_wakeup( &ctx->wakeup, 0 );
	cmd->queued_cb( cmd );
	proxy_cmd_done( cmd );
}

static void
proxy_invoke_cb( gen_cmd_t *cmd, void (*cb)( gen_cmd_t * ), int checked, const char *name )
{
	if (DFlags & FORCEASYNC) {
		debug( "%s[% 2d] Callback queue %s%s\n", cmd->ctx->label, cmd->tag, name, checked ? " (checked)" : "" );
		cmd->queued_cb = cb;
		cmd->next = NULL;
		if (checked) {
			*cmd->ctx->check_cmds_append = cmd;
			cmd->ctx->check_cmds_append = &cmd->next;
		} else {
			*cmd->ctx->done_cmds_append = cmd;
			cmd->ctx->done_cmds_append = &cmd->next;
			conf_wakeup( &cmd->ctx->wakeup, 0 );
		}
	} else {
		cb( cmd );
		proxy_cmd_done( cmd );
	}
}

static void
proxy_flush_checked_cmds( proxy_store_t *ctx )
{
	if (ctx->check_cmds) {
		*ctx->done_cmds_append = ctx->check_cmds;
		ctx->done_cmds_append = ctx->check_cmds_append;
		ctx->check_cmds_append = &ctx->check_cmds;
		ctx->check_cmds = NULL;
		conf_wakeup( &ctx->wakeup, 0 );
	}
}

static void
proxy_cancel_checked_cmds( proxy_store_t *ctx )
{
	gen_cmd_t *cmd;

	while ((cmd = ctx->check_cmds)) {
		if (!(ctx->check_cmds = cmd->next))
			ctx->check_cmds_append = &ctx->check_cmds;
		((gen_sts_cmd_t *)cmd)->sts = DRV_CANCELED;
		cmd->queued_cb( cmd );
	}
}

#if 0
//# TEMPLATE GETTER
static @type@proxy_@name@( store_t *gctx )
{
	proxy_store_t *ctx = (proxy_store_t *)gctx;

	@type@rv = ctx->real_driver->@name@( ctx->real_store );
	debug( "%sCalled @name@, ret=@fmt@\n", ctx->label, rv );
	return rv;
}
//# END

//# TEMPLATE REGULAR
static @type@proxy_@name@( store_t *gctx@decl_args@ )
{
	proxy_store_t *ctx = (proxy_store_t *)gctx;

	@pre_print_args@
	debug( "%sEnter @name@@print_fmt_args@\n", ctx->label@print_pass_args@ );
	@print_args@
	@type@rv = ctx->real_driver->@name@( ctx->real_store@pass_args@ );
	debug( "%sLeave @name@, ret=@fmt@\n", ctx->label, rv );
	return rv;
}
//# END

//# TEMPLATE REGULAR_VOID
static @type@proxy_@name@( store_t *gctx@decl_args@ )
{
	proxy_store_t *ctx = (proxy_store_t *)gctx;

	@pre_print_args@
	debug( "%sEnter @name@@print_fmt_args@\n", ctx->label@print_pass_args@ );
	@print_args@
	ctx->real_driver->@name@( ctx->real_store@pass_args@ );
	debug( "%sLeave @name@\n", ctx->label );
	@action@
}
//# END

//# TEMPLATE CALLBACK
typedef union {
	@gen_cmd_t@ gen;
	struct {
		@GEN_CMD@
		@decl_cb_state@
		void (*callback)( @decl_cb_args@void *aux );
		void *callback_aux;
		@decl_state@
	};
} @name@_cmd_t;

static void
proxy_do_@name@_cb( gen_cmd_t *gcmd )
{
	@name@_cmd_t *cmd = (@name@_cmd_t *)gcmd;

	@pre_print_cb_args@
	debug( "%s[% 2d] Callback enter @name@@print_fmt_cb_args@\n", cmd->ctx->label, cmd->tag@print_pass_cb_args@ );
	@print_cb_args@
	cmd->callback( @pass_cb_args@cmd->callback_aux );
	debug( "%s[% 2d] Callback leave @name@\n", cmd->ctx->label, cmd->tag );
}

static void
proxy_@name@_cb( @decl_cb_args@void *aux )
{
	@name@_cmd_t *cmd = (@name@_cmd_t *)aux;

	@save_cb_args@
	proxy_invoke_cb( @gen_cmd@, proxy_do_@name@_cb, @checked@, "@name@" );
}

static @type@proxy_@name@( store_t *gctx@decl_args@, void (*cb)( @decl_cb_args@void *aux ), void *aux )
{
	proxy_store_t *ctx = (proxy_store_t *)gctx;

	@name@_cmd_t *cmd = (@name@_cmd_t *)proxy_cmd_new( ctx, sizeof(@name@_cmd_t) );
	cmd->callback = cb;
	cmd->callback_aux = aux;
	@assign_state@
	@pre_print_args@
	debug( "%s[% 2d] Enter @name@@print_fmt_args@\n", ctx->label, cmd->tag@print_pass_args@ );
	@print_args@
	ctx->real_driver->@name@( ctx->real_store@pass_args@, proxy_@name@_cb, cmd );
	debug( "%s[% 2d] Leave @name@\n", ctx->label, cmd->tag );
	proxy_cmd_done( @gen_cmd@ );
}
//# END

//# UNDEFINE list_store_print_fmt_cb_args
//# UNDEFINE list_store_print_pass_cb_args
//# DEFINE list_store_print_cb_args
	if (cmd->sts == DRV_OK) {
		for (string_list_t *box = cmd->boxes; box; box = box->next)
			debug( "  %s\n", box->string );
	}
//# END

//# DEFINE load_box_pre_print_args
	static char ubuf[12];
//# END
//# DEFINE load_box_print_fmt_args , [%u,%s] (find >= %u, paired <= %u, new > %u)
//# DEFINE load_box_print_pass_args , minuid, (maxuid == UINT_MAX) ? "inf" : (nfsnprintf( ubuf, sizeof(ubuf), "%u", maxuid ), ubuf), finduid, pairuid, newuid
//# DEFINE load_box_print_args
	if (excs.size) {
		debugn( "  excs:" );
		for (uint t = 0; t < excs.size; t++)
			debugn( " %u", excs.data[t] );
		debug( "\n" );
	}
//# END
//# DEFINE load_box_print_fmt_cb_args , sts=%d, total=%d, recent=%d
//# DEFINE load_box_print_pass_cb_args , cmd->sts, cmd->total_msgs, cmd->recent_msgs
//# DEFINE load_box_print_cb_args
	if (cmd->sts == DRV_OK) {
		static char fbuf[as(Flags) + 1];
		for (message_t *msg = cmd->msgs; msg; msg = msg->next)
			debug( "  uid=%-5u flags=%-4s size=%-6u tuid=%." stringify(TUIDL) "s\n",
			       msg->uid, (msg->status & M_FLAGS) ? (proxy_make_flags( msg->flags, fbuf ), fbuf) : "?", msg->size, *msg->tuid ? msg->tuid : "?" );
	}
//# END

//# DEFINE find_new_msgs_print_fmt_cb_args , sts=%d
//# DEFINE find_new_msgs_print_pass_cb_args , cmd->sts
//# DEFINE find_new_msgs_print_cb_args
	if (cmd->sts == DRV_OK) {
		for (message_t *msg = cmd->msgs; msg; msg = msg->next)
			debug( "  uid=%-5u tuid=%." stringify(TUIDL) "s\n", msg->uid, msg->tuid );
	}
//# END

//# DEFINE fetch_msg_decl_state
	msg_data_t *data;
//# END
//# DEFINE fetch_msg_assign_state
	cmd->data = data;
//# END
//# DEFINE fetch_msg_print_fmt_args , uid=%u, want_flags=%s, want_date=%s
//# DEFINE fetch_msg_print_pass_args , msg->uid, !(msg->status & M_FLAGS) ? "yes" : "no", data->date ? "yes" : "no"
//# DEFINE fetch_msg_pre_print_cb_args
	static char fbuf[as(Flags) + 1];
	proxy_make_flags( cmd->data->flags, fbuf );
//# END
//# DEFINE fetch_msg_print_fmt_cb_args , flags=%s, date=%lld, size=%u
//# DEFINE fetch_msg_print_pass_cb_args , fbuf, (long long)cmd->data->date, cmd->data->len
//# DEFINE fetch_msg_print_cb_args
	if (cmd->sts == DRV_OK && (DFlags & DEBUG_DRV_ALL)) {
		printf( "%s=========\n", cmd->ctx->label );
		fwrite( cmd->data->data, cmd->data->len, 1, stdout );
		printf( "%s=========\n", cmd->ctx->label );
		fflush( stdout );
	}
//# END

//# DEFINE store_msg_pre_print_args
	static char fbuf[as(Flags) + 1];
	proxy_make_flags( data->flags, fbuf );
//# END
//# DEFINE store_msg_print_fmt_args , flags=%s, date=%lld, size=%u, to_trash=%s
//# DEFINE store_msg_print_pass_args , fbuf, (long long)data->date, data->len, to_trash ? "yes" : "no"
//# DEFINE store_msg_print_args
	if (DFlags & DEBUG_DRV_ALL) {
		printf( "%s>>>>>>>>>\n", ctx->label );
		fwrite( data->data, data->len, 1, stdout );
		printf( "%s>>>>>>>>>\n", ctx->label );
		fflush( stdout );
	}
//# END

//# DEFINE set_msg_flags_pre_print_args
	static char fbuf1[as(Flags) + 1], fbuf2[as(Flags) + 1];
	proxy_make_flags( add, fbuf1 );
	proxy_make_flags( del, fbuf2 );
//# END
//# DEFINE set_msg_flags_print_fmt_args , uid=%u, add=%s, del=%s
//# DEFINE set_msg_flags_print_pass_args , uid, fbuf1, fbuf2
//# DEFINE set_msg_flags_checked sts == DRV_OK

//# DEFINE trash_msg_print_fmt_args , uid=%u
//# DEFINE trash_msg_print_pass_args , msg->uid

//# DEFINE commit_cmds_print_args
	proxy_flush_checked_cmds( ctx );
//# END

//# DEFINE cancel_cmds_print_cb_args
	proxy_cancel_checked_cmds( cmd->ctx );
//# END

//# DEFINE free_store_print_args
	proxy_cancel_checked_cmds( ctx );
//# END
//# DEFINE free_store_action
	proxy_store_deref( ctx );
//# END

//# DEFINE cancel_store_print_args
	proxy_cancel_checked_cmds( ctx );
//# END
//# DEFINE cancel_store_action
	proxy_store_deref( ctx );
//# END
#endif

//# SPECIAL set_bad_callback
static void
proxy_set_bad_callback( store_t *gctx, void (*cb)( void *aux ), void *aux )
{
	proxy_store_t *ctx = (proxy_store_t *)gctx;

	ctx->bad_callback = cb;
	ctx->bad_callback_aux = aux;
}

static void
proxy_invoke_bad_callback( proxy_store_t *ctx )
{
	ctx->ref_count++;
	debug( "%sCallback enter bad store\n", ctx->label );
	ctx->bad_callback( ctx->bad_callback_aux );
	debug( "%sCallback leave bad store\n", ctx->label );
	proxy_store_deref( ctx );
}

//# EXCLUDE alloc_store
store_t *
proxy_alloc_store( store_t *real_ctx, const char *label )
{
	proxy_store_t *ctx;

	ctx = nfcalloc( sizeof(*ctx) );
	ctx->driver = &proxy_driver;
	ctx->gen.conf = real_ctx->conf;
	ctx->ref_count = 1;
	ctx->label = label;
	ctx->done_cmds_append = &ctx->done_cmds;
	ctx->check_cmds_append = &ctx->check_cmds;
	ctx->real_driver = real_ctx->driver;
	ctx->real_store = real_ctx;
	ctx->real_driver->set_bad_callback( ctx->real_store, (void (*)(void *))proxy_invoke_bad_callback, ctx );
	init_wakeup( &ctx->wakeup, proxy_wakeup, ctx );
	return &ctx->gen;
}

//# EXCLUDE parse_store
//# EXCLUDE cleanup
//# EXCLUDE get_fail_state

#include "drv_proxy.inc"
