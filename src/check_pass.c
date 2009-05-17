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
 * This file matches if the user entered the password specified.
 * NOTE: This may conflict with the challenge module if not used very carefully
 */
#include "iauthd.h"

/* A function to return MATCH_YES, if matched, MATCH_NO if it doesn't match, and MATCH_WAIT if
 * there isn't enough data yet.
 */
matched_t iauth_check_pass(actionlist_t *item, struct iauth_clients_t *client)
{
	if (client->password[0] == '\0')
		return MATCH_WAIT;

	return (strcmp(client->password, item->matchdata) == 0) ? MATCH_YES : MATCH_NO;
}

bool iauth_parse_pass(actionlist_t *item, char *line)
{
	item->matchdata = strdup(iauth_get_next_token(&line));
	return true;
}

void iauth_cleanup_pass(actionlist_t *item)
{
	if (item->matchdata)
		free(item->matchdata);
}
