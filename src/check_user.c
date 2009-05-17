/*
 * Copyright (c) 2009, Perry Lorier <isomer@undernet.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 * 
 *  * Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  * Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *  * Neither the name of Daniel Austin MBCS nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * 
 * This program matches a nick!user@host against an IRC match()
 */
#include "iauthd.h"

/* Data for this match */
struct user_data_t {
	char *ip;
	char *host;
	char *user;
	char *realname;
	char *nick;
};

/* A function to return MATCH_YES, if matched, MATCH_NO if it doesn't match, and MATCH_WAIT if
 * there isn't enough data yet.
 */
matched_t iauth_check_user(actionlist_t *item, struct iauth_clients_t *client)
{
	struct user_data_t *data = (struct user_data_t *)item->matchdata;

	/* Need their ip, host, user, realname and nick, unless they're matching against * */
	if (
		(client->host[0] == '\0' && strcmp(data->host,"*") != 0) ||
		(client->user[0] == '\0' && strcmp(data->user,"*") != 0) ||
		(client->realname[0] == '\0' && strcmp(data->realname,"*") != 0) ||
		(client->nick[0] == '\0' && strcmp(data->nick,"*") != 0))
		return MATCH_WAIT;

	if (
			(strcmp(data->ip,"*") == 0 || match(data->ip, client->ip, false)) &&
			(strcmp(data->host,"*") == 0 || match(data->host, client->host, true)) &&
			(strcmp(data->user,"*") == 0 || match(data->user, client->user, false)) &&
			(strcmp(data->realname,"*") == 0 || match(data->realname, client->realname, false)) &&
			(strcmp(data->nick,"*") == 0 || match(data->nick, client->nick, false)))
		return MATCH_YES;

	return MATCH_NO;
}

/* TODO: Change the parse to parse *!*@* style masks */
bool iauth_parse_user(actionlist_t *item, char *line)
{
	struct user_data_t *data = item->matchdata = malloc(sizeof(struct user_data_t));
	data->ip = strdup(iauth_get_next_token(&line));
	data->host = strdup(iauth_get_next_token(&line));
	data->user = strdup(iauth_get_next_token(&line));
	data->realname = strdup(iauth_get_next_token(&line));
	return true;
}

void iauth_cleanup_user(actionlist_t *item)
{
	struct user_data_t *data = (struct user_data_t *)item->matchdata;

	if (data->ip) free(data->ip);
	if (data->host) free(data->host);
	if (data->user) free(data->user);
	if (data->realname) free(data->realname);
	if (data->nick) free(data->nick);
	if (item->matchdata)
		free(item->matchdata);
}
