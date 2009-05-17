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
 * $Id: main.c,v 1.17 2008/04/18 20:46:25 danielaustin Exp $
 *
 */

#include "iauthd.h"
#include <inttypes.h>

bool iauth_reload_configs = true;

static void iauth_signal_handler(int sig)
{
	/* this function is called when the daemon is HUP'd */
	if (sig == SIGUSR1)
	{
		/* force a config reload */
		iauth_reload_configs = true;
		signal(SIGUSR1, iauth_signal_handler);
	} else
	if (sig == SIGHUP || sig == SIGINT || sig == SIGKILL || sig == SIGTERM)
	{
		/* we've been asked to terminate - save everything first */
		WriteLog("*** Got signal %d - writing caches and exiting...\n",
			sig);
		/* kill it */
		exit(0);
	}
}

char *pretty_duration(uint32_t duration, char *buf)
{
	int days, hours, mins;
	uint32_t t;
	char tmp[16];

	days = hours = mins = 0;

	t = duration;

	days = (t / 86400);
	t %= 86400;
	hours = (t / 3600);
	t %= 3600;
	mins = (t / 60);
	t %= 60;

	buf[0] = '\0';

	if (days > 0)
	{
		sprintf(tmp, "%dd", days);
		strcat(buf, tmp);
	}
	if (hours > 0)
	{
		sprintf(tmp, "%dh", hours);
		strcat(buf, tmp);
	}
	if (mins > 0)
	{
		sprintf(tmp, "%dm", mins);
		strcat(buf, tmp);
	}
	sprintf(tmp,"%ds", (int) t);
	strcat(buf, tmp);

	return buf;
}

void WriteLog(char *format, ...)
{
	va_list arglist;
	time_t ts;
	char timestr[26];
	FILE *logfp;

	if ((logfp = fopen(LOGFILE, "a")) == NULL)
		return;
	ts = time(NULL);
#ifdef HAVE_CTIME_R_2
	(void)ctime_r(&ts, timestr);
#else
	(void)ctime_r(&ts, timestr, 26);
#endif
	timestr[24] = '\0';
	fprintf(logfp, "%s | ", timestr);
	va_start(arglist, format);
	vfprintf(logfp, format, arglist);
	va_end(arglist);
	fclose(logfp);

	return;
}

void DebugLog(char *format, ...)
{
#ifdef DEBUG
	va_list arglist;
	time_t ts;
	char timestr[26];
	FILE *logfp;

	if ((logfp = fopen(LOGFILE, "a")) == NULL)
		return;
	ts = time(NULL);
#ifdef HAVE_CTIME_R_2
	(void)ctime_r(&ts, timestr);
#else
	(void)ctime_r(&ts, timestr, 26);
#endif
	timestr[24] = '\0';
	fprintf(logfp, "%s | ", timestr);
	va_start(arglist, format);
	vfprintf(logfp, format, arglist);
	va_end(arglist);
	fclose(logfp);
#endif
	return;
}

void WriteData(char *format, ...)
{
	va_list arglist;
#ifdef DEBUG
	char buf[8192];
#endif

	va_start(arglist, format);
	vfprintf(stdout, format, arglist);
	va_end(arglist);

#ifdef DEBUG
	va_start(arglist, format);
	vsprintf(buf, format, arglist);
	va_end(arglist);
	WriteLog(">>> %s", buf);
#endif
	return;
}

static void iauth_kill(uint32_t c_id, char *format, ...)
{
	va_list arglist;
	struct iauth_clients_t *client;
	char reason[1024];

	client = iauth_client_find(c_id);
	if (!client)
		return;

	va_start(arglist, format);
	vsprintf(reason, format, arglist);
	va_end(arglist);

	WriteData("k %d %s %d :%s\n", c_id, client->ip, client->remote_port,
		reason);

	(void)iauth_client_delete(c_id);
	iauth_kill_count++;

	return;
}

static void iauth_accept(uint32_t c_id)
{
	struct iauth_clients_t *client;

	client = iauth_client_find(c_id);
	if (!client)
		return;

	WriteData("D %d %s %d\n", c_id, client->ip, client->remote_port);
	client->processed = true;
	iauth_accept_count++;

	DebugLog("*** accepting %s!%s@%s [%s]\n", client->nick, client->user, client->host, client->ip);

	return;
}

static void iauth_process_user(uint32_t c_id)
{
	struct iauth_clients_t *client;

	client = iauth_client_find(c_id);

	if (!client)
		return;

	if (client->processed)
		return;

	switch (iauth_al_run(client)) {
		case ACTION_DENY:
			iauth_kill(c_id, "Failure");
			return;
		case ACTION_ALLOW:
			iauth_accept(c_id);
			return;
		case ACTION_WAIT:
			return;
	}
}

int main(int argc, char **argv)
{
	char buf[8192], *s, *t, *u, *cmd;
	char uptime[512];
	int32_t c_id;
	struct iauth_clients_t *newclient;

	if (argc > 1)
	{
		if (!strcmp(argv[1],"-v") || !strcmp(argv[1],"-V"))
		{
			printf("%s %s\n", PACKAGE, VERSION);
			printf("IRC Authentication Daemon for ircu2.10.12+\n");
			exit(0);
		}
	}

	(void)srandom((unsigned int)time(NULL));

	/* turn off stdout buffering */
	(void)setvbuf(stdout, (char *)NULL, _IONBF, 0);

	iauth_client_count = 0;
	iauth_ip_kline_count = 0;
	iauth_connection_count = 0;
	iauth_accept_count = 0;
	iauth_dnsbl_kill_count = 0;
	iauth_kill_count = 0;
	iauth_throttle_count = 0;
	iauth_challenge_passed = 0;
	iauth_challenge_failed = 0;
	iauth_challenge_timed_out = 0;
	iauth_ip_exceptions_count = 0;
	iauth_ip_stats_count = 0;
	iauth_ca_cache_count = 0;
	iauth_klines_count = 0;
	iauth_forced_count = 0;
	iauth_dnsbl_count = 0;
	iauth_dnsbl_cache_count = 0;
	start_ts = time(NULL);
	last_check = time(NULL);
	last_cache_write = time(NULL);
	iauth_clients_head = NULL;

	WriteLog("*** %s %s starting.\n", PACKAGE, VERSION);

	/* load configuration file(s) */

	/* setup signal handler(s) */
	iauth_reload_configs = false;
	signal(SIGHUP, iauth_signal_handler);
	signal(SIGINT, iauth_signal_handler);
	signal(SIGKILL, iauth_signal_handler);
	signal(SIGTERM, iauth_signal_handler);
	signal(SIGUSR1, iauth_signal_handler);

	/* announce us */
	WriteData("V :%s %s\n", PACKAGE, VERSION);			/* version string */

	/* loop here */
	while (fgets(buf, sizeof(buf), stdin))
	{
		/* need to reload config? */
		if (iauth_reload_configs)
		{
			iauth_reload_configs = false;
			/* TODO: reload config here */
		}
		/* timed entries... */
		if (last_check + 10 <= time(NULL))
		{
			actionlist_t *iter;
			last_check = time(NULL);
			/* send statistics */
			(void)pretty_duration((time(NULL) - start_ts), uptime);
			WriteData("s\n");
			WriteData("S iauth :%s %s -- up: %s\n", PACKAGE, VERSION, uptime);
			WriteData("S stats1 :%lu connections, %lu accepts, %lu kills, %.2f connections/second\n",
				iauth_connection_count, iauth_accept_count, iauth_kill_count, 
				(float) ((float)iauth_connection_count / (float)(time(NULL) - start_ts)));
			for(iter = actionlist; iter; iter=iter->next) {
				WriteData("S conf :%" PRIu32 " %" PRIu32 "%s%s "
#ifdef PROFILE
					"(%.02fs/%.02fs) "
#endif
					"%s by %s",
					iter->hit_count, iter->miss_count,
					iter->defer_count ? "*" : "",
					iter->wait_count ? "+" : "",
#ifdef PROFILE
					iter->total_cputime / attempts,
					iter->max_cputime,
#endif
					iter->action==ACTION_ALLOW ? "ALLOW" : "DENY",
					iter->match->name);
			}
		}

		/* strip trailing \r\n */
		if ((s = strchr(buf, '\n'))) *s = '\0';
		if ((s = strchr(buf, '\r'))) *s = '\0';

		DebugLog("<<< %s\n", buf);

		/* extract the client id */
		c_id = (int32_t)strtol(buf, NULL, 10);
		/* sanity check, should always be -1 or >0 */
		if (c_id==0)
		{
			WriteLog("*** unexpected c_id (%d) derived from line: %s\n", c_id, buf);
			continue;
		}

		/* extract the command */
		cmd = strchr(buf, ' ');
		if (!cmd)
		{
			WriteLog("*** malformed response received in line: %s\n", buf);
			continue;
		}
		cmd++;
		s = strchr(cmd, ' ');
		if (s)
			*s++ = '\0';

		/* ok, check commands and parse accordingly */
		if (!strcmp(cmd, "C"))
		{
			/* client connecting (s="<remoteip> <remoteport> <localip> <localport>") */
			newclient = malloc(sizeof(struct iauth_clients_t));
			if (!newclient)
			{
				WriteLog("EEE Memory allocation failure - exiting");
				exit(1);
			}
			iauth_client_count++;
			iauth_connection_count++;
			/* initialise structures */
			newclient->next = NULL;
			newclient->c_id = c_id;
			newclient->connect_ts = time(NULL);
			newclient->nick[0] = '\0';
			newclient->user[0] = '\0';
			newclient->host[0] = '\0';
			newclient->realname[0] = '\0';
			newclient->password[0] = '\0';
			newclient->have_ident = false;
			newclient->need_pass = false;
			newclient->processed = false;
			t = strchr(s, ' ');
			*t++ = '\0';
			(void)strncpy(newclient->ip, s, 15);
			newclient->ip[15] = '\0';
			(void)strncpy(newclient->host, s, 255);
			newclient->remote_ip = (uint32_t)inet_addr(s);
			s = strchr(t, ' ');
			*s++ = '\0';
			newclient->remote_port = strtol(t, NULL, 10);
			t = strchr(s, ' ');
			*t++ = '\0';
			newclient->local_ip = (uint32_t)inet_addr(s);
			newclient->local_port = strtol(t, NULL, 10);
			/* add to client list */
			if (!iauth_clients_head)
			{
				iauth_clients_head = newclient;
			} else {
				newclient->next = iauth_clients_head;
				iauth_clients_head = newclient;
			}
			/* run raw IP checks */
			iauth_process_user(c_id);
		} else
		if (!strcmp(cmd, "d"))
		{
			/* dns lookup timed out (s=null) */
		} else
		if (!strcmp(cmd, "D"))
		{
			/* client is disconnecting (s=null) */
			(void)iauth_client_delete(c_id);
		} else
		if (!strcmp(cmd, "E"))
		{
			/* error received (s="<details>") */
			DebugLog("*** Error received: %s\n", buf);
		} else
		if (!strcmp(cmd, "H"))
		{
			/* hurry up (client issued PING response, s=null) */
			(void)iauth_process_user(c_id);
		} else
		if (!strcmp(cmd, "M"))
		{
			/* server is connecting (s="<servername> <maxclients>") */
			t = strchr(s, ' ');
			*t++ = '\0';
			(void)strncpy(iauth_remote_server, s, 255);
			iauth_remote_server[255] = '\0';
			iauth_remote_server_maxclients = (uint32_t)strtoul(t, NULL, 10);
			WriteLog("*** server '%s' connected (%lu max clients)\n",
				iauth_remote_server,
				iauth_remote_server_maxclients);
			WriteData("O AUR\n");						/* options string */
		} else
		if (!strcmp(cmd, "n"))
		{
			/* nick info received (s="<nick>") */
			(void)iauth_client_set_info(c_id, s, NULL, false, NULL, NULL, NULL);
			(void)iauth_process_user(c_id);
		} else
		if (!strcmp(cmd, "N"))
		{
			/* hostname received (from dns lookup, s="<hostname>") */
			(void)iauth_client_set_info(c_id, NULL, NULL, false, s, NULL, NULL);
			(void)iauth_process_user(c_id);
		} else
		if (!strcmp(cmd, "P"))
		{
			/* password (or response) received (s="<pass/response>") */
			s++;
			iauth_client_set_info(c_id, NULL, NULL, true, NULL, NULL, s);
			(void)iauth_process_user(c_id);
		} else
		if (!strcmp(cmd, "T"))
		{
			/* client registered (s=null) */
			iauth_client_set_info(c_id, NULL, NULL, true, NULL, NULL, "");
			(void)iauth_process_user(c_id);
		} else
		if (!strcmp(cmd, "u"))
		{
			/* username received from ident lookup (s="<username>") */
			(void)iauth_client_set_info(c_id, NULL, s, true, NULL, NULL, NULL);
			(void)iauth_process_user(c_id);
		} else
		if (!strcmp(cmd, "U"))
		{
			/* user details received from USER command (s="<username> <hostname/mode> <servername> :<realname>") */
			t = strchr(s, ' ');
			*t++ = '\0';
			u = strchr(t, ':');
			u++;
			(void)iauth_client_set_info(c_id, NULL, s, false, NULL, u, NULL);
			(void)iauth_process_user(c_id);
		} else
		{
			/* unknown command */
			WriteLog("WWW Unknown command (%s) received in line: %s\n", cmd, buf);
		}
	}
	exit(0);
}

