/*-
 * Copyright (c) 2020 Mindaugas Rasiukevicius <rmind at noxt eu>
 * Copyright (c) 2009-2013 The NetBSD Foundation, Inc.
 * All rights reserved.
 *
 * This material is based upon work partially supported by The
 * NetBSD Foundation under a contract with Mindaugas Rasiukevicius.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE NETBSD FOUNDATION, INC. AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * NPF packet handler.
 *
 * This is the main entry point to the NPF where packet processing happens.
 * There are some important synchronization rules:
 *
 *	1) Lookups into the connection database and configuration (ruleset,
 *	tables, etc) are protected by Epoch-Based Reclamation (EBR);
 *
 *	2) The code in the critical path (protected by EBR) should generally
 *	not block (that includes adaptive mutex acquisitions);
 *
 *	3) Where it will blocks, references should be acquired atomically,
 *	while in the critical path, on the relevant objects.
 */

#ifdef _KERNEL
#include <sys/cdefs.h>
__KERNEL_RCSID(0, "$NetBSD: npf_handler.c,v 1.49 2020/05/30 14:16:56 rmind Exp $");

#include <sys/types.h>
#include <sys/param.h>

#include <sys/mbuf.h>
#include <sys/mutex.h>
#include <net/if.h>
#include <net/pfil.h>
#include <sys/socketvar.h>

#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netinet/tcp_timer.h>
#include <netinet/udp.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#if !defined(_NPF_TESTING)
#include <netinet/in_pcb.h>
#include <netinet/tcp_var.h>
#include <netinet/udp_var.h>

#include <secmodel/secmodel.h>
#include <secmodel/jail/jail.h>
#endif
#endif

#include "npf_impl.h"
#include "npf_conn.h"

#if defined(_NPF_STANDALONE)
#define	m_freem(m)		npf->mbufops->free(m)
#define	m_clear_flag(m,f)
#else
#define	m_clear_flag(m,f)	(m)->m_flags &= ~(f)
#endif

#ifndef INET6
#define ip6_reass_packet(x, y)	ENOTSUP
#endif

static int
npf_reassembly(npf_t *npf, npf_cache_t *npc, bool *mff)
{
	nbuf_t *nbuf = npc->npc_nbuf;
	int error = EINVAL;
	struct mbuf *m;

	*mff = false;
	m = nbuf_head_mbuf(nbuf);

	if (npf_iscached(npc, NPC_IP4) && npf->ip4_reassembly) {
		error = ip_reass_packet(&m);
	} else if (npf_iscached(npc, NPC_IP6) && npf->ip6_reassembly) {
		error = ip6_reass_packet(&m, npc->npc_hlen);
	} else {
		/*
		 * Reassembly is disabled: just pass the packet through
		 * the ruleset for inspection.
		 */
		return 0;
	}

	if (error) {
		/* Reassembly failed; free the mbuf, clear the nbuf. */
		npf_stats_inc(npf, NPF_STAT_REASSFAIL);
		m_freem(m);
		memset(nbuf, 0, sizeof(nbuf_t));
		return error;
	}
	if (m == NULL) {
		/* More fragments should come. */
		npf_stats_inc(npf, NPF_STAT_FRAGMENTS);
		*mff = true;
		return 0;
	}

	/*
	 * Reassembly is complete, we have the final packet.
	 * Cache again, since layer 4 data is accessible now.
	 */
	nbuf_init(npf, nbuf, m, nbuf->nb_ifp);
	npc->npc_info = 0;

	if (npf_cache_all(npc) & (NPC_IPFRAG|NPC_FMTERR)) {
		return EINVAL;
	}
	npf_stats_inc(npf, NPF_STAT_REASSEMBLY);
	return 0;
}


#if defined(_KERNEL) && !defined(_NPF_TESTING)

static kauth_cred_t
npf_get_outgoing_socket_cred(npf_cache_t *npc)
{
	struct mbuf *m = nbuf_head_mbuf(npc->npc_nbuf);
	struct m_tag *mt;
	struct socket *so;

	if (m == NULL) {
		return NULL;
	}
	mt = m_tag_find(m, PACKET_TAG_SO);
	if (mt == NULL) {
		return NULL;
	}
	so = *(struct socket **)(mt + 1);
	if (so == NULL) {
		return NULL;
	}
	return so->so_cred;
}

static kauth_cred_t
npf_get_inbound_owner_cred(const npf_cache_t *npc)
{
	struct inpcb *inp = NULL;
	const in_port_t sport = npf_iscached(npc, NPC_TCP) ?
	    npc->npc_l4.tcp->th_sport : npc->npc_l4.udp->uh_sport;
	const in_port_t dport = npf_iscached(npc, NPC_TCP) ?
	    npc->npc_l4.tcp->th_dport : npc->npc_l4.udp->uh_dport;

	if (npf_iscached(npc, NPC_IP4)) {
		struct in_addr src4, dst4;

		memcpy(&src4, npc->npc_ips[NPF_SRC], sizeof(src4));
		memcpy(&dst4, npc->npc_ips[NPF_DST], sizeof(dst4));

		if (npf_iscached(npc, NPC_TCP)) {
			inp = inpcb_lookup(&tcbtable, src4, sport, dst4, dport, 0);
			if (inp == NULL) {
				inp = inpcb_lookup_bound(&tcbtable, dst4, dport);
			}
		} else if (npf_iscached(npc, NPC_UDP)) {
			inp = inpcb_lookup(&udbtable, src4, sport, dst4, dport, 0);
			if (inp == NULL) {
				inp = inpcb_lookup_bound(&udbtable, dst4, dport);
			}
		}
	} else if (npf_iscached(npc, NPC_IP6)) {
		struct in6_addr src6, dst6;

		memcpy(&src6, npc->npc_ips[NPF_SRC], sizeof(src6));
		memcpy(&dst6, npc->npc_ips[NPF_DST], sizeof(dst6));

		if (npf_iscached(npc, NPC_TCP)) {
			inp = in6pcb_lookup(&tcbtable, &src6, sport, &dst6, dport, 0, 0);
			if (inp == NULL) {
				inp = in6pcb_lookup_bound(&tcbtable, &dst6, dport, 0);
			}
		} else if (npf_iscached(npc, NPC_UDP)) {
			inp = in6pcb_lookup(&udbtable, &src6, sport, &dst6, dport, 0, 0);
			if (inp == NULL) {
				inp = in6pcb_lookup_bound(&udbtable, &dst6, dport, 0);
			}
		}
	}

	if (inp == NULL || inp->inp_socket == NULL) {
		return NULL;
	}
	return inp->inp_socket->so_cred;
}

static bool
npf_rule_jail_match(const npf_rule_t *rl, npf_cache_t *npc, int di)
{
	const char *jailname = npf_rule_getjailname(rl);
	kauth_cred_t cred;
	struct secmodel_jail_eval_cred_matches_args args;
	bool match = false;
	int error;

	if (!npf_iscached(npc, NPC_TCP) && !npf_iscached(npc, NPC_UDP)) {
		/*
		 * Jail-aware owner matching is only meaningful for TCP/UDP,
		 * because these protocols map naturally to local sockets.
		 */
		return jailname == NULL;
	}

	if (di & PFIL_OUT) {
		cred = npf_get_outgoing_socket_cred(npc);
		if (cred == NULL) {
			return false;
		}
		if (jailname == NULL) {
			return true;
		}
	} else {
		cred = npf_get_inbound_owner_cred(npc);
		if (cred == NULL) {
			/*
			 * If no local owner socket can be resolved, explicit jail
			 * qualifiers must not match. Unqualified rules keep legacy
			 * behavior and therefore continue to match.
			 */
			return jailname == NULL;
		}
		if (jailname == NULL) {
			/*
			 * For inbound traffic without an explicit jail qualifier,
			 * only host sockets (jail id 0) are accepted by design.
			 * The secmodel_jail API uses name == NULL to express host.
			 */
			args.cred = cred;
			args.name = NULL;
			error = secmodel_eval(SECMODEL_JAIL_ID,
			    SECMODEL_JAIL_EVAL_CRED_MATCHES, &args, &match);
			if (error != 0) {
				return true;
			}
			return match;
		}
	}

	args.cred = cred;
	args.name = jailname;
	error = secmodel_eval(SECMODEL_JAIL_ID,
	    SECMODEL_JAIL_EVAL_CRED_MATCHES, &args, &match);
	if (error != 0) {
		/*
		 * If secmodel_jail is unavailable, explicit jail qualifiers are
		 * treated as non-matching while unqualified rules preserve the
		 * legacy NPF behavior.
		 */
		return npf_rule_getjailname(rl) == NULL;
	}
	return match;
}

#else

static bool
npf_rule_jail_match(const npf_rule_t *rl, npf_cache_t *npc, int di)
{
	/*
	 * The standalone test environment has no kernel sockets or secmodel
	 * providers. Keep legacy behavior by treating jail qualifiers as
	 * non-restrictive in this build mode.
	 */
	(void)rl;
	(void)npc;
	(void)di;
	return true;
}

#endif

static inline bool
npf_packet_bypass_tag_p(nbuf_t *nbuf)
{
	uint32_t ntag;
	return nbuf_find_tag(nbuf, &ntag) == 0 && (ntag & NPF_NTAG_PASS) != 0;
}

/*
 * npfk_packet_handler: main packet handling routine for layer 3.
 *
 * Note: packet flow and inspection logic is in strict order.
 */
__dso_public int
npfk_packet_handler(npf_t *npf, struct mbuf **mp, ifnet_t *ifp, int di)
{
	nbuf_t nbuf;
	npf_cache_t npc;
	npf_conn_t *con;
	npf_rule_t *rl;
	npf_rproc_t *rp;
	int error, decision, flags;
	npf_match_info_t mi;
	bool mff;

	KASSERT(ifp != NULL);

	/*
	 * Initialize packet information cache.
	 * Note: it is enough to clear the info bits.
	 */
	nbuf_init(npf, &nbuf, *mp, ifp);
	memset(&npc, 0, sizeof(npf_cache_t));
	npc.npc_ctx = npf;
	npc.npc_nbuf = &nbuf;

	mi.mi_di = di;
	mi.mi_rid = 0;
	mi.mi_retfl = 0;

	*mp = NULL;
	decision = NPF_DECISION_BLOCK;
	error = 0;
	rp = NULL;
	con = NULL;

	/* Cache everything. */
	flags = npf_cache_all(&npc);

	/* Malformed packet, leave quickly. */
	if (flags & NPC_FMTERR) {
		error = EINVAL;
		goto out;
	}

	/* Determine whether it is an IP fragment. */
	if (__predict_false(flags & NPC_IPFRAG)) {
		/* Pass to IPv4/IPv6 reassembly mechanism. */
		error = npf_reassembly(npf, &npc, &mff);
		if (error) {
			goto out;
		}
		if (mff) {
			/* More fragments should come. */
			return 0;
		}
	}

	/* Just pass-through if specially tagged. */
	if (npf_packet_bypass_tag_p(&nbuf)) {
		goto pass;
	}

	/* Inspect the list of connections (if found, acquires a reference). */
	con = npf_conn_inspect(&npc, di, &error);

	/* If "passing" connection found - skip the ruleset inspection. */
	if (con && npf_conn_pass(con, &mi, &rp)) {
		npf_stats_inc(npf, NPF_STAT_PASS_CONN);
		KASSERT(error == 0);
		goto pass;
	}
	if (__predict_false(error)) {
		if (error == ENETUNREACH)
			goto block;
		goto out;
	}

	/* Acquire the lock, inspect the ruleset using this packet. */
	int slock = npf_config_read_enter(npf);
	npf_ruleset_t *rlset = npf_config_ruleset(npf);

	rl = npf_ruleset_inspect(&npc, rlset, di, NPF_LAYER_3);
	if (__predict_false(rl == NULL)) {
		const bool pass = npf_default_pass(npf);
		npf_config_read_exit(npf, slock);

		if (pass) {
			npf_stats_inc(npf, NPF_STAT_PASS_DEFAULT);
			goto pass;
		}
		npf_stats_inc(npf, NPF_STAT_BLOCK_DEFAULT);
		goto block;
	}

	/*
	 * Apply jail qualifier semantics after byte-code match so the
	 * selected rule is also validated against socket ownership context.
	 */
	if (!npf_rule_jail_match(rl, &npc, di)) {
		npf_config_read_exit(npf, slock);
		npf_stats_inc(npf, NPF_STAT_BLOCK_RULESET);
		goto block;
	}

	/*
	 * Get the rule procedure (acquires a reference) for association
	 * with a connection (if any) and execution.
	 */
	KASSERT(rp == NULL);
	rp = npf_rule_getrproc(rl);

	/* Conclude with the rule and release the lock. */
	error = npf_rule_conclude(rl, &mi);
	npf_config_read_exit(npf, slock);

	if (error) {
		npf_stats_inc(npf, NPF_STAT_BLOCK_RULESET);
		goto block;
	}
	npf_stats_inc(npf, NPF_STAT_PASS_RULESET);

	/*
	 * Establish a "pass" connection, if required.  Just proceed if
	 * connection creation fails (e.g. due to unsupported protocol).
	 */
	if ((mi.mi_retfl & NPF_RULE_STATEFUL) != 0 && !con) {
		con = npf_conn_establish(&npc, di,
		    (mi.mi_retfl & NPF_RULE_GSTATEFUL) == 0);
		if (con) {
			/*
			 * Note: the reference on the rule procedure is
			 * transferred to the connection.  It will be
			 * released on connection destruction.
			 */
			npf_conn_setpass(con, &mi, rp);
		}
	}

pass:
	decision = NPF_DECISION_PASS;
	KASSERT(error == 0);

	/*
	 * Perform NAT.
	 */
	error = npf_do_nat(&npc, con, di);

block:
	/*
	 * Execute the rule procedure, if any is associated.
	 * It may reverse the decision from pass to block.
	 */
	if (rp && !npf_rproc_run(&npc, rp, &mi, &decision)) {
		if (con) {
			npf_conn_release(con);
		}
		npf_rproc_release(rp);
		/* mbuf already freed */
		return 0;
	}

out:
	/*
	 * Release the reference on a connection.  Release the reference
	 * on a rule procedure only if there was no association.
	 */
	if (con) {
		npf_conn_release(con);
	} else if (rp) {
		npf_rproc_release(rp);
	}

	/* Get the new mbuf pointer. */
	if ((*mp = nbuf_head_mbuf(&nbuf)) == NULL) {
		return error ? error : ENOMEM;
	}

	/* Pass the packet if decided and there is no error. */
	if (decision == NPF_DECISION_PASS && !error) {
		/*
		 * XXX: Disable for now, it will be set accordingly later,
		 * for optimisations (to reduce inspection).
		 */
		m_clear_flag(*mp, M_CANFASTFWD);
		return 0;
	}

	/*
	 * Block the packet.  ENETUNREACH is used to indicate blocking.
	 * Depending on the flags and protocol, return TCP reset (RST) or
	 * ICMP destination unreachable.
	 */
	if (mi.mi_retfl && npf_return_block(&npc, mi.mi_retfl)) {
		*mp = NULL;
	}

	if (!error) {
		error = ENETUNREACH;
	}

	if (*mp) {
		/* Free the mbuf chain. */
		m_freem(*mp);
		*mp = NULL;
	}
	return error;
}
