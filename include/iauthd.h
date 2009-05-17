/*
 * Copyright (c) 2007, Daniel Austin MBCS <daniel@undernet.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification,
 * are permitted provided that the following conditions are met:
 * 
 *  * Redistributions of source code must retain the above copyright notice, this
 *    list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Daniel Austin MBCS nor the names of its contributors
 *    may be used to endorse or promote products derived from this software without
 *    specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * $Id: iauthd.h,v 1.13 2008/04/18 20:45:05 danielaustin Exp $
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "config.h"

#include <stdbool.h>
#ifdef HAVE_STDINT_H
#include <stdint.h>
#else
#ifdef HAVE_INTTYPES_H
#include <inttypes.h>
#endif
#endif
#include <stdarg.h>
#include <time.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <signal.h>
/* pcre regex library */
#ifdef HAVE_PCRE_H
#include <pcre.h>
#endif

#include "iauthd_config.h"

/* structures */
struct iauth_clients_t {
	int32_t			c_id;						/* client id */
	time_t			connect_ts;					/* connection timestamp */
	char			ip[16];						/* textual ip */
	uint32_t		remote_ip;
	uint16_t		remote_port;
	uint32_t		local_ip;
	uint16_t		local_port;
	char			nick[17];
	char			user[17];
	char			host[256];
	char			realname[256];
	char			expected_pass[33];				/* pass (if needed */
	char			password[33];					/* pass as provided by user */
	/* flags */
	bool			have_ident;
	bool			need_pass;
	bool			processed;
	struct iauth_clients_t	*next;
} *iauth_clients_head;

/* global variables */
time_t		start_ts;
time_t		last_check;
time_t		last_cache_write;
char		iauth_remote_server[256];
uint32_t	iauth_remote_server_maxclients;
uint32_t	iauth_client_count;
uint32_t	iauth_ip_kline_count;
uint32_t	iauth_throttle_count;
uint32_t	iauth_connection_count;
uint32_t	iauth_accept_count;
uint32_t	iauth_dnsbl_kill_count;
uint32_t	iauth_kill_count;
uint32_t	iauth_challenge_passed;
uint32_t	iauth_challenge_failed;
uint32_t	iauth_challenge_timed_out;
uint32_t	iauth_ip_exceptions_count;
uint32_t	iauth_ip_stats_count;
uint32_t	iauth_ca_cache_count;
uint32_t	iauth_klines_count;
uint32_t	iauth_forced_count;
uint32_t	iauth_dnsbl_count;
uint32_t	iauth_dnsbl_cache_count;

/* function prototypes */
#ifndef HAVE_STRSEP
char *strsep(char **str, const char *delims);
#endif

bool match(const char *pattern, const char *string, bool ci);

char *pretty_duration(uint32_t duration, char *buf);
void WriteLog(char *format, ...);
void DebugLog(char *format, ...);
void WriteData(char *format, ...);
/* void iauth_kill(uint32_t c_id, char *format, ...); */
/* void iauth_accept(uint32_t c_id); */
/* struct iauth_ip_stats_t *iauth_ip_stats_get(uint32_t ip); */
/* void iauth_ip_stats_add(uint32_t ip); */
/* void iauth_ip_stats_remove(uint32_t ip); */

char *iauth_get_next_token(char **s);

struct iauth_clients_t *iauth_client_find(int32_t c_id);
void iauth_client_delete(int32_t c_id);
void iauth_client_set_info(int32_t c_id, char *nick, char *user, bool ident, char *host, char *realname, char *pass);

typedef enum action_t { ACTION_DENY, ACTION_ALLOW, ACTION_WAIT } action_t;
typedef enum matched_t { MATCH_YES, MATCH_NO, MATCH_WAIT } matched_t;


typedef struct actionlist_t {
	action_t action;
	struct matchtype_t *match;
	time_t last_hit;	/* Time when the rule was last hit */
	uint32_t hit_count;	/* # times rule returned MATCH_YES */
	uint32_t miss_count;	/* # times rule returned MATCH_NO */
	uint32_t wait_count;	/* # times rule returned MATCH_WAIT */
	uint32_t defer_count;	/* # times processing stopped at this rule due to WAIT's */
#ifdef PROFILE
	double total_cputime;	/* total amount of cputime spent on this match */
	uint32_t attempts;	/* total amount of times this rule was called */
	double max_cputime;	/* largest amount of cpu time spent on this match */
#endif
	int lineno;		/* Line number of this rule in the file */
	void *matchdata;	/* misc data for the match */
	struct actionlist_t *next;
} actionlist_t;

struct matchtype_t {
	const char *name;
	matched_t (*check)(actionlist_t *item, struct iauth_clients_t *client);
	bool (*parse)(actionlist_t *, char *args);
	void (*cleanup)(actionlist_t *);
}; 


void iauth_al_reloadfile(void);
action_t iauth_al_run(struct iauth_clients_t *client);

struct cache_t;
void add_cache_entry(struct cache_t **head, void *key, int keylen, bool value, int duration);
typedef enum { CACHE_FALSE, CACHE_TRUE, CACHE_MISS } cache_result_t;
cache_result_t find_cache_entry(struct cache_t **head, void *key, int keylen);
void clear_cache(struct cache_t **head);

matched_t iauth_check_all(actionlist_t *item, struct iauth_clients_t *client);
matched_t iauth_check_challenge(actionlist_t *item, struct iauth_clients_t *client);
matched_t iauth_check_dnsrbl(actionlist_t *item, struct iauth_clients_t *client);
matched_t iauth_check_ident(actionlist_t *item, struct iauth_clients_t *client);
matched_t iauth_check_pass(actionlist_t *item, struct iauth_clients_t *client);
matched_t iauth_check_program(actionlist_t *item, struct iauth_clients_t *client);
matched_t iauth_check_regex(actionlist_t *item, struct iauth_clients_t *client);
matched_t iauth_check_user(actionlist_t *item, struct iauth_clients_t *client);

bool iauth_parse_challenge(actionlist_t *item, char *line);
bool iauth_parse_dnsrbl(actionlist_t *item, char *line);
bool iauth_parse_none(actionlist_t *item, char *line);
bool iauth_parse_pass(actionlist_t *item, char *line);
bool iauth_parse_program(actionlist_t *item, char *line);
bool iauth_parse_user(actionlist_t *item, char *line);
bool iauth_parse_regex(actionlist_t *item, char *line);

void iauth_cleanup_challenge(actionlist_t *item);
void iauth_cleanup_dnsrbl(actionlist_t *item);
void iauth_cleanup_none(actionlist_t *item);
void iauth_cleanup_pass(actionlist_t *item);
void iauth_cleanup_program(actionlist_t *item);
void iauth_cleanup_regex(actionlist_t *item);
void iauth_cleanup_user(actionlist_t *item);

extern actionlist_t *actionlist;
