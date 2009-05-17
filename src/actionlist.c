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
 * This file deals with the list of actions to perform as a ueer connects 
 */
#include "iauthd.h"
#include <stdio.h>
#include <stdbool.h>

#define ACTIONLIST_FILE "/tmp/actionlist.conf"

actionlist_t *actionlist=NULL;
actionlist_t *actionlisttail=NULL;

static void iauth_al_writefile()
{
	FILE *fp = fopen(ACTIONLIST_FILE,"w");
	if (!fp) 
		return;
	fprintf(fp,"# iauthd configuration file\n");
	fprintf(fp,"# Syntax:\n");
	fprintf(fp,"#  ALLOW BY <method> <arguments>\n");
	fprintf(fp,"#  DENY BY <method> <arguments>\n");
	fclose(fp);
}

static struct matchtype_t matches[] = {
 { "all", 	iauth_check_all, 	iauth_parse_none, 	iauth_cleanup_none },
 { "challenge", iauth_check_challenge, 	iauth_parse_challenge, 	iauth_cleanup_challenge },
 { "ident", 	iauth_check_ident, 	iauth_parse_none, 	iauth_cleanup_none },
 { "dnsrbl", 	iauth_check_dnsrbl, 	iauth_parse_dnsrbl, 	iauth_cleanup_dnsrbl },
 { "pass",	iauth_check_pass,	iauth_parse_pass,	iauth_cleanup_pass },
 { "program",	iauth_check_program,	iauth_parse_program,	iauth_cleanup_program },
 { "regex", 	iauth_check_regex, 	iauth_parse_regex, 	iauth_cleanup_regex },
 { "user", 	iauth_check_user, 	iauth_parse_user, 	iauth_cleanup_user },
 { NULL, NULL, NULL, NULL }
};

void iauth_al_reloadfile()
{
	FILE *fp;
	char buf[8192];
	int linenum=0;

	if ((fp = fopen(ACTIONLIST_FILE,"r")) == NULL) 
	{
		iauth_al_writefile();
		return;
	}

	while (fgets(buf, sizeof(buf), fp)) 
	{
		char *s, *t;
		actionlist_t *item;
		++linenum;
		
		/* Remove trailing newlines */
		if ((s = strchr(buf, '\n'))) *s = '\0';
		if ((s = strchr(buf, '\r'))) *s = '\0';
		/* ignore blank lines + comments */
		if (buf[0] == '\0' || buf[0] == '#' || buf[0] == ';')
			continue;
		/* parse line */
		item = malloc(sizeof(actionlist_t));
		item->lineno=linenum;
		item->last_hit = 0;
		item->hit_count = 0;
		item->miss_count = 0;
		item->wait_count = 0;
		item->defer_count = 0;
#ifdef PROFILE
		item->total_cputime = 0;
		item->attempts = 0;
		item->max_cputime = -1;
#endif
		if (!item) 
		{
			fclose(fp);
			WriteLog("*** memory allocation error during actionlist config read.\n");
			exit(1);
		}
		/* (ALLOW|DENY) (ALL|BY (CHALLENGE|....) <args> */
		t = iauth_get_next_token(&s);
		if (strcasecmp(t,"allow") == 0) 
		{
			item->action=ACTION_ALLOW;
		} else if (strcasecmp(t,"deny") == 0) {
			item->action=ACTION_DENY;
		} else {
			WriteLog("Parse error on line %d of actionlist config: expected ALLOW or DENY. Ignoring\n");
			free(item);
			continue;
		}
		
		t = iauth_get_next_token(&s);
		if (strcasecmp(t,"all") == 0) {
			item->match = &matches[0];
		} else if (strcasecmp(t,"by") != 0) {
			WriteLog("Parse error on line %d of actionlist config: expected BY or ALL. Ignoring\n");
			free(item);
			continue;
		} else { 
			t = iauth_get_next_token(&s);
			for (item->match=&matches[1]; item->match->name; ++item->match) {
				if (strcasecmp(item->match->name, t) == 0) 
					break;
			}

			if (!item->match->name) {
				WriteLog("Parse error on line %d of actionlist config: expected match name. Ignoring\n");
				free(item);
				continue;
			}
	
			if (!item->match->parse(item, s)) {
				free(item);
				continue;
			}
		}
		item->next = NULL;
		
		if (actionlisttail == NULL) {
			actionlist=actionlisttail=item;
		}
		else {
			actionlisttail->next=item;
			actionlisttail=item;
		}
	}
}

action_t iauth_al_run(struct iauth_clients_t *client)
{
	actionlist_t *it = actionlist;
	bool is_delayed=false;
	action_t delayed_action = ACTION_WAIT;

	while (it) {
		matched_t res;
#ifdef PROFILE
		struct timeval start,end;
		double duration;
#endif
		/* 
		 * 
		 * Matchers can return "MATCH_YES" to say that they match this rule,
		 * "MATCH_NO" to say that they don't match this rule, and "MATCH_WAIT" to say that
		 * they can't match this rule because there isn't enough information yet.
		 *
		 * When stepping through rules
		 * if we don't match, ignore this rule, and continue on.
		 * if we do match, and theres no delayed matches above, return.
		 * if this is a delayed match for an "ALLOW", and we hit an ALLOW later on,
		 *  we don't have to wait for the first delayed match, just ALLOW.
		 * if this is a delayed match for a "DENY", and we hit an "DENY" later on,
		 *  we don't have to wait for the first delayed match, just DENY.
		 * otherwise, we don't know if the first rule is going to override this rule,
		 * so we need to punt and say "WAIT" (ie: try again later when theres more 
		 * information)
		 */
		if (is_delayed && delayed_action != it->action) {
			++it->defer_count;
			return ACTION_WAIT;
		}
#ifdef PROFILE
		gettimeofday(&start,NULL);
#endif
		res = it->match->check(it, client);
#ifdef PROFILE
		gettimeofday(&end,NULL);
		duration = (start.tv_sec + start.tv_usec/1000000) - (end.tv_sec + end.tv_usec/1000000);
		it->total_cputime += duration;
		it->attempts++;
		if (duration > it->max_cputime)
			it->max_cputime = duration;
#endif
		switch (res) {
			case MATCH_YES:
				it->hit_count++;
				it->last_hit=time(NULL);
				return it->action;
			case MATCH_WAIT:
				it->wait_count++;
				is_delayed=true;
				delayed_action = it->action;
				break;
			case MATCH_NO:
				it->miss_count++;
				break;
		}
		it=it->next;
	}
	/* Default allow */
	return ACTION_ALLOW;
}
