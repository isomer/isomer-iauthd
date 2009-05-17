/*
 * Copyright (c) 2009, Perry Lorier <isomer@undernet.org>
 * Copyright (c) 2007, Daniel Austin MBCS <daniel@undernet.org>
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
 * This file matches if a user is present in a DNSRBL
 */
#include "iauthd.h"

struct dnsrbl_data_t {
	char *hostname;
	char *expected;
	struct cache_t *cache;
};

static bool iauth_dnsbl_check(struct iauth_clients_t *client, char *dnsbl, char *expected)
{
	struct sockaddr_in *s_inaddr = NULL;
	struct addrinfo hints, *res;
	char host[512], buf[INET6_ADDRSTRLEN];
	int error;
	int client_addr[4] = { 0 };

	/* reverse the IP octets for dnsnl lookup, append dnsbl host */
	sscanf(client->ip, "%d.%d.%d.%d", &client_addr[0], &client_addr[1], &client_addr[2], &client_addr[3]);
	sprintf(host, "%d.%d.%d.%d.%s", client_addr[3], client_addr[2], client_addr[1], client_addr[0], dnsbl);

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_INET;

	DebugLog("*** calling getaddrinfo('%s')\n", host);
	error = getaddrinfo(host, NULL, &hints, &res);
	/* if call fails, negative result */
	if (!res)
	{
		DebugLog("*** got no response from getaddrinfo()\n");
		return false;
	}
	if (res->ai_addr)
	{
		/* TODO: Check all the IP addresses returned if more than one */
		s_inaddr = (struct sockaddr_in *) (res->ai_addr);
		sprintf(host, "%s", inet_ntop(AF_INET,
			&(s_inaddr->sin_addr), buf, INET6_ADDRSTRLEN));
		DebugLog("*** got '%s' from getaddrinfo() - expecting '%s'\n",
			host, expected);
		if (!strcmp(host, expected))
		{
			/* direct match, positive result */
			DebugLog("*** positive dnsbl result\n");
			(void)freeaddrinfo(res);
			return true;
		}
	}
	else {
		DebugLog("*** No results from getaddrinfo()\n");
	}
	DebugLog("*** negative dnsbl result\n");
	/* either incorrect response, or no IP returned - negative result */
	(void)freeaddrinfo(res);
	return false;
}

matched_t iauth_check_dnsrbl(actionlist_t *item, struct iauth_clients_t *client)
{
	bool ret;
	struct dnsrbl_data_t *data = item->matchdata;

	/* check cache first */
	switch (find_cache_entry(&data->cache, &client->remote_ip, sizeof(client->remote_ip))) {
		case CACHE_FALSE: return MATCH_NO;
		case CACHE_TRUE : return MATCH_YES;
		case CACHE_MISS : break;
	}
	
	ret = iauth_dnsbl_check(client, data->hostname, data->expected);

	add_cache_entry(&data->cache, &client->remote_ip, sizeof(client->remote_ip), ret, 3600);

	return ret ? MATCH_YES : MATCH_NO;
}

bool iauth_parse_dnsrbl(actionlist_t *item, char *line)
{
	struct dnsrbl_data_t *data = item->matchdata = malloc(sizeof(struct dnsrbl_data_t));
	data->hostname = strdup(iauth_get_next_token(&line));
	data->expected = strdup(iauth_get_next_token(&line));
	data->cache = NULL;
	return false;
}

void iauth_cleanup_dnsrbl(actionlist_t *item)
{
	struct dnsrbl_data_t *data = item->matchdata;
	clear_cache(&data->cache);
	if (data->hostname)
		free(data->hostname);
	if (data->expected)
		free(data->expected);
	free(data);
}
