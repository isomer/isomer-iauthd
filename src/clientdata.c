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
 * $Id: clientdata.c,v 1.3 2007/11/16 07:49:07 kewlio Exp $
 *
 */

#include "iauthd.h"

struct iauth_clients_t *iauth_client_find(int32_t c_id)
{
	struct iauth_clients_t	*client;

	for (client = iauth_clients_head; client != NULL; client = client->next)
	{
		if (client->c_id == c_id)
			return client;
	}
	return NULL;
}

void iauth_client_delete(int32_t c_id)
{
	struct iauth_clients_t	*client, *oldclient;

	oldclient = NULL;
	for (client = iauth_clients_head; client != NULL; client = client->next)
	{
		if (client->c_id == c_id)
		{
			iauth_client_count--;
			if (!oldclient)
			{
				iauth_clients_head = client->next;
				free(client);
				return;
			} else {
				oldclient->next = client->next;
				free(client);
				return;
			}
		}
		oldclient = client;
	}
	return;
}

void iauth_client_set_info(int32_t c_id, char *nick, char *user, bool ident, char *host, char *realname, char *pass)
{
	struct iauth_clients_t	*client;
        char tmp[17], *t;

        if (user)
	{
		if (ident)
		{
	                (void)strncpy(tmp, user, 16);
		} else {
	                t = tmp;
	                t++;
	                tmp[0] = '~';
	                (void)strncpy(t, user, 15);
	        }
	}

	for (client = iauth_clients_head; client != NULL; client = client->next)
	{
		if (client->c_id == c_id)
		{
			if (nick)
			{
				(void)strncpy(client->nick, nick, 16);
				client->nick[16] = '\0';
			}
			if (user)
			{
				/* if we're already idented, dont both updating again */
				if (!client->have_ident)
				{
					(void)strncpy(client->user, tmp, 16);
					client->user[16] = '\0';
				}
			}
			if (ident)
				client->have_ident = true;
			if (host)
			{
				(void)strncpy(client->host, host, 255);
				client->host[255] = '\0';
			}
			if (realname)
			{
				(void)strncpy(client->realname, realname, 255);
				client->realname[255] = '\0';
			}
			if (pass)
			{
				(void)strncpy(client->password, pass, 12);
				client->password[12] = '\0';
			}
			return;
		}
	}

	return;
}

