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
 * $Id: match.c,v 1.5 2007/12/10 22:25:13 kewlio Exp $
 *
 */

#include "iauthd.h"

bool match(const char *pattern, const char *string, bool ci)
{
	const char *cp = NULL, *mp = NULL;
	bool isIP, isCIDR;
	char ch;
	int i, j, dots, CIDR;
	char CIDRip[16];
	uint32_t mask_ip, client_ip;

	/* never match an empty string */
	if (string && string[0]=='\0')
		return false;

	/* always match a "*" pattern */
	if (!strcmp(pattern, "*"))
		return true;

	/* check for CIDR matching */
	cp = pattern;
	isIP = true;
	isCIDR = false;
	dots = 0;
	i = 0;
	while ((ch = *cp++))
	{
		if (ch == '.')
		{
			dots++;
			if (dots > 3)
			{
				isIP = false;
				break;
			}
		}
		if (ch == '/')
		{
			isCIDR = true;
			break;
		}
		if (isIP && ((ch > '9') || (ch < '0')) && ch != '.')
		{
			isIP = false;
			break;
		}
		CIDRip[i++] = ch;
	}
	if (!isIP)
		isCIDR = false;
	if (isCIDR)
	{
		/* it appears we have a valid IP followed by a CIDR length */
		CIDR = strtol(cp, NULL, 10);
		/* do we need to "fix" the mask? */
		if (CIDRip[i-1]=='.')
		{
			CIDRip[i++] = '0';
		}
		for (j = dots; j < 3; j++)
		{
			CIDRip[i++] = '.';
			CIDRip[i++] = '0';
		}
		CIDRip[i] = '\0';
		mask_ip = ntohl(inet_addr(CIDRip));
		client_ip = ntohl(inet_addr(string));
		if (client_ip > 0)
		{
			/* handle special case - 0 is always true */
			if (CIDR == 0)
				return true;
			mask_ip >>= (32-CIDR);
			mask_ip <<= (32-CIDR);
			client_ip >>= (32-CIDR);
			client_ip <<= (32-CIDR);
			if (mask_ip == client_ip)
				return true;
		}
	}

	/* wildcard match - NOTE: ci = whether we're case insensitive */
	while ((*string) && (*pattern != '*'))
	{
		if (!ci)
		{
			if ((*pattern != *string) && (*pattern != '?'))
				return false;
		} else {
			if ((tolower(*pattern) != tolower(*string)) && (*pattern != '?'))
				return false;
		}
		pattern++;
		string++;
	}

	while (*string)
	{
		if (*pattern == '*')
		{
			if (!*++pattern)
				return true;
			mp = pattern;
			cp = string+1;
		} else {
			if (!ci)
			{
				if ((*pattern == *string) || (*pattern == '?'))
				{
					pattern++;
					string++;
				} else {
					pattern = mp;
					string = cp++;
				}
			} else {
				if ((tolower(*pattern) == tolower(*string)) || (*pattern == '?'))
				{
					pattern++;
					string++;
				} else {
					pattern = mp;
					string = cp++;
				}
			}
		}
	}

	while (*pattern == '*')
		pattern++;
	return !*pattern;
}

