/*
 * (c) Copyright 2016 G. Campana
 * (c) Copyright 2016 Quarkslab
 *
 * This file is part of Cappsule.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#define _GNU_SOURCE
#include <err.h>
#include <stdlib.h>
#include <sys/time.h>

#include <json-c/json.h>

#include "api.h"


struct pending_capsule *find_pending_by_client(struct context *ctx,
					       struct client *client)
{
	struct pending_capsule *pending;

	for (pending = ctx->pending; pending != NULL; pending = pending->next) {
		if (pending->client == client)
			return pending;
	}

	return NULL;
}

struct pending_capsule *find_pending_by_capsule(struct context *ctx,
						struct capsule *capsule)
{
	struct pending_capsule *pending;

	for (pending = ctx->pending; pending != NULL; pending = pending->next) {
		if (pending->capsule == capsule)
			return pending;
	}

	return NULL;
}

/**
 * Remove an element from the pending list.
 */
void delete_pending(struct context *ctx, struct pending_capsule *pending)
{
	if (pending->prev != NULL)
		pending->prev->next = pending->next;
	if (pending->next != NULL)
		pending->next->prev = pending->prev;
	if (pending == ctx->pending)
		ctx->pending = pending->next;

	/* prefer NULL pointer dereference over use-after-free */
	pending->prev = NULL;
	pending->next = NULL;

	free(pending);
}

struct pending_capsule *create_pending(struct context *ctx,
				       struct capsule *capsule,
				       struct client *client)
{
	struct pending_capsule *pending;

	pending = malloc(sizeof(*pending));
	if (pending == NULL) {
		warn("malloc");
		return NULL;
	}

	pending->capsule = capsule;
	pending->client = client;
	gettimeofday(&pending->creation, NULL);

	pending->prev = NULL;
	if (ctx->pending == NULL) {
		pending->next = NULL;
	} else {
		ctx->pending->prev = pending;
		pending->next = ctx->pending;
	}
	ctx->pending = pending;

	return pending;
}

int get_pending_timeout(struct context *ctx)
{
	struct pending_capsule *p;
	struct timeval diff, now;
	int result, timeout_ms;

	gettimeofday(&now, NULL);
	result = -1;

	for (p = ctx->pending; p != NULL; p = p->next) {
		timeval_subtract(&diff, &now, &p->creation);
		timeout_ms = diff.tv_sec * 1000 + diff.tv_usec / 1000;
		if (timeout_ms <= INITIALIZATION_TIMEOUT)
			timeout_ms = INITIALIZATION_TIMEOUT - timeout_ms;
		else
			timeout_ms = 0;

		if (result == -1 || timeout_ms < result)
			result = timeout_ms;
	}

	return result;
}

int send_creation_response_helper(struct context *ctx, struct json_object *jobj,
				  struct client *client)
{
	if (send_json_response(client, jobj) != 0) {
		handle_client_error(ctx, client);
		return -1;
	}

	return 0;
}

static void delete_expired_pending(struct context *ctx,
				   struct pending_capsule *pending)
{
	struct json_object *jobj;
	char msg[128];

	/* client is always valid: if an error occurs, pending capsule is
	 * removed */
	snprintf(msg, sizeof(msg),
		 "devices initialization timed out (capsule: %d)",
		 pending->capsule->capsule_id);
	jobj = build_json_error(msg);
	send_creation_response_helper(ctx, jobj, pending->client);

	delete_pending(ctx, pending);
}

/**
 * Delete every pending capsules whose timeout expired.
 */
void delete_expired_pendings(struct context *ctx)
{
	struct pending_capsule *p;
	struct timeval diff, now;
	int timeout_ms;

	gettimeofday(&now, NULL);

	for (p = ctx->pending; p != NULL; p = p->next) {
		timeval_subtract(&diff, &now, &p->creation);
		timeout_ms = diff.tv_sec * 1000 + diff.tv_usec / 1000;
		if (timeout_ms > INITIALIZATION_TIMEOUT) {
			kill_capsule(ctx->channel_fd, p->capsule->capsule_id);

			/* pending capsule is removed while the list is being
			 * walked, but it's safe */
			delete_expired_pending(ctx, p);
		}
	}
}

/**
 * Send response of "create" command and delete pending.
 */
err_t send_creation_response(struct context *ctx, struct capsule *capsule,
			     bool success, const char *errmsg)
{
	struct pending_capsule *pending;
	struct json_object *jobj;

	pending = find_pending_by_capsule(ctx, capsule);
	if (pending == NULL) {
		/* happen when pending has already expired */
		return SUCCESS;
	}

	if (success) {
		jobj = build_json_result(1, "capsule_id",
					 json_object_new_int(capsule->capsule_id));
	} else {
		jobj = build_json_error(errmsg);
	}

	send_creation_response_helper(ctx, jobj, pending->client);
	delete_pending(ctx, pending);

	return SUCCESS;
}
