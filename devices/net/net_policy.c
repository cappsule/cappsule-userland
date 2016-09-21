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

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <net/if.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/fcntl.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_tun.h>
#include <linux/limits.h>

#include "userland.h"
#include "policy.h"
#include "exec.h"
#include "net_common.h"
#include "net_policy.h"


static inline void get_iface_chain(char *iface, char *proto, char *chain, size_t chain_sz)
{
	snprintf(chain, chain_sz, "fw-%s-%s", iface, proto);
}

/*
 * Setup filtering for interface tun-caps-N -> all other interfaces.
 */
static int add_outgoing_traffic_filters(char *iface, char *proto, struct array *rules)
{
	unsigned int i;
	struct net_value target;
	struct sockaddr_in saddr_in;
	char target_host[64];
	char target_port[32];
	char chain[IFNAMSIZ + 16];
	char log_prefix[NF_LOG_PREFIX_MAX_SZ];

	get_iface_chain(iface, proto, chain, sizeof(chain));

	/* Ensures the interface is properly destroyed before creation. */
	NF_UNLINK_OUTPUT_FROM_CHAIN(iface, proto, chain);
	NF_DESTROY_CHAIN(chain);

	if (NF_CREATE_CHAIN(chain) != 0) {
		warnx("cannot create chain %s", chain);
		return -1;
	}

	if (NF_LINK_OUTPUT_TO_CHAIN(iface, proto, chain) != 0) {
		warnx("cannot forward packets from %s to %s", iface, chain);
		return -1;
	}

	if (NF_SET_CHAIN_POLICY(chain, "DROP") != 0) {
		warnx("cannot set policy for chain %s", chain);
		return -1;
	}

	snprintf(log_prefix, sizeof(log_prefix), "Capsule:%s:DROP:", iface);
	if (NF_CHAIN_LOG(chain, NF_LOG_LEVEL, log_prefix) != 0) {
		warnx("cannot set log level for chain %s", chain);
		return -1;
	}

	if (rules == NULL)
		return 0;

	for (i = 0; i < rules->n; i++) {
		target = rules->hosts[i];

		if (target.min_ipaddr == 0 &&
		    target.max_ipaddr == 0xffffffff &&
		    target.min_port == 0 &&
		    target.max_port == 0)
		{
			if (NF_SET_CHAIN_POLICY(chain, "ACCEPT") != 0) {
				warnx("cannot set accept policy for chain %s", chain);
				return -1;
			}

			return 0;
		}

		/* Fill target host buffer */
		saddr_in.sin_addr.s_addr = target.min_ipaddr;
		strncpy(target_host, inet_ntoa(saddr_in.sin_addr), sizeof(target_host) - 1);

		if (target.min_ipaddr != target.max_ipaddr) {
			strncat(target_host, "-", sizeof(target_host) - 1);
			saddr_in.sin_addr.s_addr = target.max_ipaddr;
			strncat(target_host, inet_ntoa(saddr_in.sin_addr), sizeof(target_host) - 1);
		}

		/* Fill target port buffer */
		if (target.min_port == target.max_port) {
			snprintf(target_port, sizeof(target_port),
				"%hu", target.min_port);
		}
		else {
			snprintf(target_port, sizeof(target_port),
				"%hu:%hu", target.min_port, target.max_port);
		}

		if (NF_CHAIN_ALLOW_OUTPUT_IP_PORT(chain, proto, target_host, target_port) != 0) {
			warnx("cannot create rule for chain %s", chain);
			return -1;
		}
	}

	return 0;
}

/*
 * Setup filtering for all traffic going to tun-caps-N.
 * This will also filter traffic from tun-caps-N to itself.
 *
 * The capsule must be able to access the guiserver and the fsserver.
 */
static int setup_default_input_filters(char *iface)
{
	char chain[IFNAMSIZ + 16];
	char log_prefix[NF_LOG_PREFIX_MAX_SZ];

	get_iface_chain(iface, "input", chain, sizeof(chain));

	NF_UNLINK_INPUT_FROM_CHAIN(iface, chain);
	NF_DESTROY_CHAIN(chain);

	if (NF_CREATE_CHAIN(chain) != 0) {
		warnx("cannot create chain %s", chain);
		return -1;
	}

	if (NF_LINK_INPUT_TO_CHAIN(iface, chain) != 0) {
		warnx("cannot forward packets from %s to %s", iface, chain);
		return -1;
	}

	if (NF_SET_CHAIN_POLICY(chain, "DROP") != 0) {
		warnx("cannot set policy for chain %s", chain);
		return -1;
	}

	snprintf(log_prefix, sizeof(log_prefix), "Capsule:%s:DROP:", iface);
	if (NF_CHAIN_LOG(chain, NF_LOG_LEVEL, log_prefix) != 0) {
		warnx("cannot set log level for chain %s", chain);
		return -1;
	}

	if (NF_CHAIN_ALLOW_ESTABLISHED(chain) != 0) {
		warnx("cannot set conntrack rule for chain %s", chain);
		return -1;
	}

	return 0;
}

static void flush_input_network_filters(char *iface)
{
	char chain[IFNAMSIZ + 16];

	get_iface_chain(iface, "input", chain, sizeof(chain));

	NF_UNLINK_INPUT_FROM_CHAIN(iface, chain);
	NF_DESTROY_CHAIN(chain);
}

static void flush_output_network_filters(char *iface, char *proto)
{
	char chain[IFNAMSIZ + 16];

	get_iface_chain(iface, proto, chain, sizeof(chain));

	NF_UNLINK_OUTPUT_FROM_CHAIN(iface, proto, chain);
	NF_DESTROY_CHAIN(chain);
}

void cleanup_interface_policy(char *iface)
{
	char log_prefix[NF_LOG_PREFIX_MAX_SZ];

	flush_input_network_filters(iface);
	flush_output_network_filters(iface, "tcp");
	flush_output_network_filters(iface, "udp");

	snprintf(log_prefix, sizeof(log_prefix), "Capsule:%s:DROP:", iface);
	NF_INTERFACE_UNLOG_OUTPUT(iface, NF_LOG_LEVEL, log_prefix);
	NF_UNSET_INTERFACE_OUTPUT_POLICY(iface, DEFAULT_NET_FILTER);
}

static int setup_default_output_filters(char *iface)
{
	char log_prefix[NF_LOG_PREFIX_MAX_SZ];

	/* Remove default filter if already present. */
	NF_UNSET_INTERFACE_OUTPUT_POLICY(iface, DEFAULT_NET_FILTER);
	if (NF_SET_INTERFACE_OUTPUT_POLICY(iface, DEFAULT_NET_FILTER) != 0) {
		warnx("cannot set default filter for interface %s", iface);
		return -1;
	}

	snprintf(log_prefix, sizeof(log_prefix), "Capsule:%s:DROP:", iface);

	/* Remove outgoing log filter if already present. */
	NF_INTERFACE_UNLOG_OUTPUT(iface, NF_LOG_LEVEL, log_prefix);
	if (NF_INTERFACE_LOG_OUTPUT(iface, NF_LOG_LEVEL, log_prefix) != 0) {
		warnx("cannot set log level for interface %s", iface);
		return -1;
	}

	return 0;
}

static int configure_interface_policy(char *iface, struct policy *policy)
{
	if (setup_default_output_filters(iface) != 0)
		return -1;

	if (setup_default_input_filters(iface) != 0)
		return -1;

	if (add_outgoing_traffic_filters(iface, "udp", policy->net.udp) != 0)
		return -1;

	if (add_outgoing_traffic_filters(iface, "tcp", policy->net.tcp) != 0)
		return -1;

	return 0;
}

int set_tun_network_policy(int tunfd, struct policy *policy)
{
	struct ifreq ifr;

	if (ioctl(tunfd, TUNGETIFF, &ifr) < 0) {
		warn("ioctl(TUNGETIFF)");
		close(tunfd);
		return -1;
	}

	if (configure_interface_policy(ifr.ifr_name, policy) != 0) {
		warnx("cannot configure policy for interface %s", ifr.ifr_name);
		close(tunfd);
		return -1;
	}

	return 0;
}

// vim: noet:ts=8:sw=8:
