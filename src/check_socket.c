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
 * Similar to check_program, this file asks a socket if a user should match
 * or not.
 */
#include "iauthd.h"
#include <stdarg.h>
#include <unistd.h>

/* Data for this match */
struct socket_data_t {
	char *socket;
	int fd;
};

static void send_message(struct socket_data_t *data, char *format,...)
{
	char buf[8192];
	va_list arglist;

	va_start(arglist, format);
	vsnprintf(buf, sizeof(buf), format, arglist);
	va_end(arglist);
	
	write(data->fd, buf, strlen(buf));
}

static bool recv_message(struct socket_data_t *data, char *buffer, size_t len)
{
	int ret=read(data->fd, buffer, len-1);
	/* Error?  Close the connection so it can be reopened later */
	if (ret == -1) {
		close(data->fd);
		data->df = 0;
	}
	else {
		buffer[ret]='\0';
	}

	return true;
}

/* A function to return MATCH_YES, if matched, MATCH_NO if it doesn't match, and MATCH_WAIT if
 * there isn't enough data yet.
 */
matched_t iauth_check_socket(actionlist_t *item, struct iauth_clients_t *client)
{
	struct socket_data_t *data = (struct socket_data_t *)item->matchdata;
	char buffer[1024];

	/* Need their ip, host, user, realname and nick */
	if (client->host[0] == '\0' 
			|| client->user[0] == '\0' 
			|| client->realname == '\0'
			|| client->nick == '\0')
		return MATCH_WAIT;

	if (data->fd == -1) {
		if (strchr(data->socket,"/")) {
			data->fd = socket(AF_UNIX, SOCK_STREAM, 0);
			data->fd = connect();
		}
		else {
			getaddrinfo();
		}
	}

	send_message(data,"? %s %s!%s@%s/%s\n",
			client->ip,
			client->nick, client->user, client->host, client->realname);

	recv_message(data,buffer,sizeof(buffer));

	if (buffer[0] == 'Y')
		return MATCH_YES;
	else
		return MATCH_NO;
}

bool iauth_parse_socket(actionlist_t *item, char *line)
{
	struct socket_data_t *data = item->matchdata = malloc(sizeof(struct socket_data_t));

	data->socket = strdup(line);
	data->fd = -1;
	data->laststart = 0;
	
	return true;
}

void iauth_cleanup_socket(actionlist_t *item)
{
	struct socket_data_t *data = (struct socket_data_t *)item->matchdata;

	if (data->fd) {
		send_message(data, "Q\n"); /* Quit */
		close(data->fd);
	}

	if (data->socket) free(data->socket);
	if (item->matchdata)
		free(item->matchdata);
}
