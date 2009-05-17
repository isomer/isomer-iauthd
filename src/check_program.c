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
 * This module connects to an external program and asks it to match the user
 */
#include "iauthd.h"
#include <stdarg.h>
#include <unistd.h>

/* Data for this match */
struct command_data_t {
	char *commandline;
	int stdin_fd;
	int stdout_fd;
	time_t laststart;
};

static void send_message(struct command_data_t *data, char *format,...)
{
	char buf[8192];
	va_list arglist;

	va_start(arglist, format);
	vsnprintf(buf, sizeof(buf), format, arglist);
	va_end(arglist);
	
	write(data->stdin_fd, buf, strlen(buf));
}

static bool recv_message(struct command_data_t *data, char *buffer, size_t len)
{
	int ret=read(data->stdout_fd, buffer, len-1);
	/* Error?  Close the connection so it can be reopened later */
	if (ret == -1) {
		close(data->stdin_fd);
		close(data->stdout_fd);
		data->stdin_fd = data->stdout_fd = -1;
	}
	else {
		buffer[ret]='\0';
	}

	return true;
}

/* A function to return MATCH_YES, if matched, MATCH_NO if it doesn't match, and MATCH_WAIT if
 * there isn't enough data yet.
 */
matched_t iauth_check_program(actionlist_t *item, struct iauth_clients_t *client)
{
	struct command_data_t *data = (struct command_data_t *)item->matchdata;
	char buffer[1024];

	/* Need their ip, host, user, realname and nick */
	if (client->host[0] == '\0' 
			|| client->user[0] == '\0' 
			|| client->realname == '\0'
			|| client->nick == '\0')
		return MATCH_WAIT;

	if (data->stdin_fd == -1) {
		int stdin_fds[2], stdout_fds[2];
		time_t now = time(NULL);
		/* Program is crashing too often, rate limit */
		if (now - data->laststart < 10)
			return MATCH_NO;
		data->laststart = now;
		pipe(stdin_fds);
		pipe(stdout_fds);
		if (fork() == 0) {
			/* I'm the child */
			dup2(stdin_fds[0],0);
			dup2(stdout_fds[1],1);
			close(stdin_fds[0]);
			close(stdin_fds[1]);
			close(stdout_fds[0]);
			close(stdout_fds[1]);
			execl("/bin/sh","-c",data->commandline,NULL);
			_exit(1);
		}
		else {
			data->stdin_fd = stdin_fds[1];
			data->stdout_fd = stdout_fds[0];
			close(stdin_fds[0]);
			close(stdout_fds[1]);
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

bool iauth_parse_program(actionlist_t *item, char *line)
{
	struct command_data_t *data = item->matchdata = malloc(sizeof(struct command_data_t));

	data->commandline = strdup(line);
	data->stdin_fd = -1;
	data->stdout_fd = -1;
	data->laststart = 0;
	
	return true;
}

void iauth_cleanup_program(actionlist_t *item)
{
	struct command_data_t *data = (struct command_data_t *)item->matchdata;

	if (data->stdin_fd) {
		send_message(data, "Q\n"); /* Quit */
		close(data->stdin_fd);
		close(data->stdout_fd);
	}

	if (data->commandline) free(data->commandline);
	if (item->matchdata)
		free(item->matchdata);
}
