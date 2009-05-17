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
 * This file provides a cache abstraction layer for other parts of the program
 * to use.
 */
#include "iauthd.h"

struct cache_t {
	char *key;
	int keylen;
	bool value;
	time_t expires;
	struct cache_t *next;
};

void add_cache_entry(struct cache_t **head, void *key, int keylen, bool value, int duration)
{
	struct cache_t *cache;
	cache = malloc(sizeof(struct cache_t));
	cache->key = malloc(keylen);
	memcpy(cache->key, key, keylen);
	cache->value = value;
	cache->expires = duration + time(NULL);
	cache->next = *head;
	*head = cache;
}

cache_result_t find_cache_entry(struct cache_t **head, void *key, int keylen)
{
	struct cache_t *it, *next;
	time_t now = time(NULL);
	for(it=*head;it;it=next) {
		next=it->next;
		if (it->expires < now) {
			if (it == *head) {
				*head = next;
			}
			free(it->key);
			free(it);
		}
		else if (it->keylen == keylen && memcmp(it->key, key, keylen) == 0) {
			return it->value ? CACHE_TRUE : CACHE_FALSE;
		}
	}
	return CACHE_MISS;
}

void clear_cache(struct cache_t **head)
{
	while (*head) {
		struct cache_t *tmp = *head;
		*head = (*head)->next;
		free(tmp->key);
		free(tmp);
	}
}

