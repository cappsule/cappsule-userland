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

#ifndef _TUN_H
#define _TUN_H

#define TUN_DEVICE	"/dev/net/tun"
#define TUN_INTERFACE	"tun-caps-"

#define NF_LOG_LEVEL "info"
#define NF_LOG_PREFIX_MAX_SZ 30

#define DEFAULT_NET_FILTER "DROP"

#define NF_DESTROY_CHAIN(chain)						\
	({								\
		EXEC_CMD_QUIET("iptables", "-F", chain);		\
		EXEC_CMD_QUIET("iptables", "-X", chain);		\
	})								\

#define NF_CREATE_CHAIN(chain)						\
	EXEC_CMD_QUIET("iptables", "-N", chain)				\

#define NF_INSERT_CHAIN_RULE(chain, target, args...)			\
	EXEC_CMD_QUIET("iptables", "-I", chain, "-j", target, ##args)	\

#define NF_REMOVE_CHAIN_RULE(chain, target, args...)			\
	EXEC_CMD_QUIET("iptables", "-D", chain, "-j", target, ##args)	\

#define NF_INSERT_INPUT_RULE(iface, target, args...)			\
	NF_INSERT_CHAIN_RULE("INPUT", target, "-i", iface, ##args)	\

#define NF_REMOVE_INPUT_RULE(iface, target, args...)			\
	NF_REMOVE_CHAIN_RULE("INPUT", target, "-i", iface, ##args)	\

#define NF_INSERT_INPUT_FORWARD_RULE(iface, target, args...)		\
	NF_INSERT_CHAIN_RULE("FORWARD", target, "-o", iface, ##args)	\

#define NF_REMOVE_INPUT_FORWARD_RULE(iface, target, args...)		\
	NF_REMOVE_CHAIN_RULE("FORWARD", target, "-o", iface, ##args)	\

#define NF_INSERT_OUTPUT_FORWARD_RULE(iface, target, args...)		\
	NF_INSERT_CHAIN_RULE("FORWARD", target, "-i", iface, ##args)	\

#define NF_REMOVE_OUTPUT_FORWARD_RULE(iface, target, args...)		\
	NF_REMOVE_CHAIN_RULE("FORWARD", target, "-i", iface, ##args)	\

#define NF_LINK_OUTPUT_TO_CHAIN(iface, proto, chain)			\
	NF_INSERT_OUTPUT_FORWARD_RULE(iface, chain, "-p", proto)	\

#define NF_UNLINK_OUTPUT_FROM_CHAIN(iface, proto, chain)		\
	NF_REMOVE_OUTPUT_FORWARD_RULE(iface, chain, "-p", proto)	\

#define NF_LINK_INPUT_TO_CHAIN(iface, chain)				\
	({								\
		NF_INSERT_INPUT_FORWARD_RULE(iface, chain);		\
		NF_INSERT_INPUT_RULE(iface, chain);			\
	})								\

#define NF_UNLINK_INPUT_FROM_CHAIN(iface, chain)			\
	({								\
		NF_REMOVE_INPUT_FORWARD_RULE(iface, chain);		\
		NF_REMOVE_INPUT_RULE(iface, chain);			\
	})								\

#define NF_SET_INTERFACE_OUTPUT_POLICY(iface, policy)			\
	NF_INSERT_OUTPUT_FORWARD_RULE(iface, policy)			\

#define NF_UNSET_INTERFACE_OUTPUT_POLICY(iface, policy)			\
	NF_REMOVE_OUTPUT_FORWARD_RULE(iface, policy)			\

#define NF_INTERFACE_LOG_OUTPUT(iface, level, prefix)			\
	NF_INSERT_OUTPUT_FORWARD_RULE(iface, "LOG",			\
			  "--log-level", level,				\
			  "--log-prefix", prefix)			\

#define NF_INTERFACE_UNLOG_OUTPUT(iface, level, prefix)			\
	NF_REMOVE_OUTPUT_FORWARD_RULE(iface, "LOG",			\
			  "--log-level", level,				\
			  "--log-prefix", prefix)			\

#define NF_SET_CHAIN_POLICY(chain, policy)				\
	NF_INSERT_CHAIN_RULE(chain, policy)				\

#define NF_CHAIN_LOG(chain, level, prefix)				\
	NF_INSERT_CHAIN_RULE(chain, "LOG",				\
			"--log-level", level,				\
			"--log-prefix", prefix)				\

#define NF_CHAIN_ALLOW_OUTPUT_IP_PORT(chain, proto, ip, port)		\
	NF_INSERT_CHAIN_RULE(chain, "ACCEPT",				\
			"-p", proto,					\
			"-m", "iprange", "-m", "multiport",		\
			"--dst-range", ip,				\
			"--dports", port)				\

#define NF_CHAIN_ALLOW_INPUT_PORT(chain, proto, port)			\
	NF_INSERT_CHAIN_RULE(chain, "ACCEPT",				\
			"-p", proto,					\
			"-m", "multiport",				\
			"--dports", port)				\

#define NF_CHAIN_ALLOW_ESTABLISHED(chain)				\
	NF_INSERT_CHAIN_RULE(chain, "ACCEPT",				\
			"-m", "state",					\
			"--state", "RELATED,ESTABLISHED")		\

int remove_tun(int tunfd);
int set_tun_file(int channel_fd, unsigned int index, int tunfd);
int set_tun_network_policy(int tunfd, struct policy *policy);
int setup_tun_ifconfig(struct ifreq *ifr, unsigned int id);
void cleanup_interface_policy(char *iface);

#endif

// vim: noet:ts=8:sw=:
