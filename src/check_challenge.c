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
 * This file authenticates a user if they can correctly answer a challenge
 */
#include "iauthd.h"
struct challenge_data_t  {
	char *password;
};

static void iauth_ca_generate_pass(char *pass, size_t len)
{
	const char *con[] = { "b","br", 
			"c","ch","chr","cr",
			"d","dr",
			"f","fr",
			"g","gr",
			"h",
			"j",
			"k","kr",
			"l",
			"m",
			"n",
			"p",
			"qu",
			"r",
			"s","st","str",
			"t","tr","tt",
			"v",
			"w",
			"x",
			"z" };
	const char *vowel[] = { "a","ae","e", "i","ie","o","u","y" };
	int count=2;

	while (len>1 && count>0) {
		int c=random() % (sizeof(con)/sizeof(con[0]));
		int v=random() % (sizeof(vowel)/sizeof(vowel[0]));
		if (strlen(con[c]) + strlen(con[v]) + 1 > len) 
			break;
		strcpy(pass,con[c]);
		pass += strlen(con[c]);
		len -= strlen(con[c]);
		strcpy(pass,vowel[v]);
		pass += strlen(vowel[v]);
		len -= strlen(vowel[v]);
		count--;
	}
}

static void iauth_send_challenge(struct iauth_clients_t *client, char *reason)
{       
	/* Already have sent one */
	if (client->need_pass)
		return;

	iauth_ca_generate_pass(client->expected_pass, sizeof(client->expected_pass));

	client->need_pass = true;

	/* send the challenge */
	WriteData("C %d %s %d :%s, to continue to connect you must type /QUOTE PASS %s\n",
		client->c_id, client->ip, client->remote_port, reason, client->expected_pass);
	DebugLog("*** sending: C %d %s %d :%s, to continue to connect you must type /QUOTE PASS %s\n",
		client->c_id, client->ip, client->remote_port, reason, client->expected_pass);
	return;
}

matched_t iauth_check_challenge(actionlist_t *item, struct iauth_clients_t *client)
{
	if (client->password[0] != '\0') {
		if (strcmp(client->password, client->expected_pass) == 0)
			return MATCH_YES;
		return MATCH_NO;
	}
	else if (!client->need_pass)
		iauth_send_challenge(client, item->matchdata);
	/* We're waiting for them to send a pass */
	return MATCH_WAIT;
}

bool iauth_parse_challenge(actionlist_t *item, char *line)
{
	item->matchdata = strdup(line);
	return true;
}

void iauth_cleanup_challenge(actionlist_t *item)
{
	free(item->matchdata);
}


