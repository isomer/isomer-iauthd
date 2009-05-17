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
 * This file matches a user against a regular expression.
 */
#include "iauthd.h"

struct regex_data_t {
	char pattern[2048];
	pcre *re;
	pcre_extra *extra;
	struct cache_t *cache;
};

matched_t iauth_check_regex(actionlist_t *item, struct iauth_clients_t *client)
{
	char tmp[8192];
	int ret;
	int erroffset;
	struct regex_data_t *data = (struct regex_data_t *)item->matchdata;

	if (client->nick[0]=='\0' 
			|| client->user[0]=='\0' 
			|| client->host[0]=='\0' 
			|| client->realname[0] == '\0')
		return MATCH_WAIT;

	/* construct match string */
	sprintf(tmp, "%s!%s@%s/%s",
		client->nick,
		client->user,
		client->host,
		client->realname
	);

	switch (find_cache_entry(&data->cache, tmp, strlen(tmp))) {
		case CACHE_FALSE: return MATCH_NO;
		case CACHE_TRUE:  return MATCH_YES;
		case CACHE_MISS:
			break;
	}

	ret = pcre_exec(data->re, data->extra, 
			tmp, strlen(tmp), 0, 0, &erroffset, 1);

	switch (ret) {
		case 0:
			add_cache_entry(&data->cache, tmp, strlen(tmp), true, 3600);
			return MATCH_YES;
		case PCRE_ERROR_NOMATCH:
			add_cache_entry(&data->cache, tmp, strlen(tmp), false, 3600);
			return MATCH_NO;
		default:
			/* Error */
			WriteLog("*** regex match error while matching '%s' against '%s' (got %d)",
				tmp, data->pattern, ret);
			return MATCH_NO;
	}
}

bool iauth_parse_regex(actionlist_t *item, char *line)
{
	struct regex_data_t *data;
	const char *errptr;
	int erroffset;
	
	data = item->matchdata = malloc(sizeof(struct regex_data_t *));
	data->cache = NULL;

	data->re = pcre_compile(line, 0, &errptr, &erroffset, NULL);
	if (!data->re) 
	{
		fprintf(stderr, "Error on line %d: regex compilation failed at %d due to %s\n",
			item->lineno, erroffset, errptr);
		return false;
	}

	data->extra = pcre_study(data->re, 0, &errptr);
	if (!data->extra && errptr) {
		fprintf(stderr, "Error on line %d: regex study failed at %d due to %s\n",
			item->lineno, erroffset, errptr);
		return false;
	}

	return true;
}

void iauth_cleanup_regex(actionlist_t *item)
{
	struct regex_data_t *data = (struct regex_data_t *)item->matchdata;
	if (data->extra)
		free(data->extra);
	if (data->re)
		free(data->re);
	clear_cache(&data->cache);
	free(data);
}
