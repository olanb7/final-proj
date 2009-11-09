/*
 * tcpipsend.{cc,hh} -- sends TCP/IP packets
 * Thomer M. Gil
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "tcpipsend.hh"
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#ifdef CLICK_LINUXMODULE
# include <net/checksum.h>
#endif
CLICK_DECLS

TCPIPSend::TCPIPSend()
{
}

TCPIPSend::~TCPIPSend()
{
}

int
TCPIPSend::send_write_handler(const String &conf, Element *e, void *, ErrorHandler *errh)
{
  Vector<String> args;
  TCPIPSend* me = (TCPIPSend *) e;

  unsigned int saddr, daddr;
  uint16_t sport, dport;
  unsigned char bits;
  unsigned seqn, ackn;
  if(cp_va_space_kparse(conf, me, errh,
			"SRC", cpkP+cpkM, cpIPAddress, &saddr,
			"SPORT", cpkP+cpkM, cpTCPPort, &sport,
			"DST", cpkP+cpkM, cpIPAddress, &daddr,
			"DPORT", cpkP+cpkM, cpTCPPort, &dport,
			"SEQNO", cpkP+cpkM, cpUnsigned, &seqn,
			"ACKNO", cpkP+cpkM, cpUnsigned, &ackn,
			"FLAGS", cpkP+cpkM, cpByte, &bits,
			cpEnd) < 0)
    return -1;

  Packet *p = me->make_packet(saddr, daddr, sport, dport, seqn, ackn, bits);
  me->output(0).push(p);
  return 0;
}



Packet *
TCPIPSend::make_packet(unsigned int saddr, unsigned int daddr,
                       unsigned short sport, unsigned short dport,
		       unsigned int seqn, unsigned int ackn,
                       unsigned char bits)
{
  struct click_ip *ip;
  struct click_tcp *tcp;
  WritablePacket *q = Packet::make(sizeof(*ip) + sizeof(*tcp));
  if (q == 0) {
    click_chatter("in TCPIPSend: cannot make packet!");
    assert(0);
  }
  memset(q->data(), '\0', q->length());
  ip = (struct click_ip *) q->data();
  tcp = (struct click_tcp *) (ip + 1);
  q->set_ip_header(ip, sizeof(click_ip));

  // IP fields
  ip->ip_v = 4;
  ip->ip_hl = 5;
  ip->ip_tos = 0;
  ip->ip_len = htons(q->length());
  ip->ip_id = htons(0);
  ip->ip_off = htons(IP_DF);
  ip->ip_ttl = 255;
  ip->ip_p = IP_PROTO_TCP;
  ip->ip_sum = 0;
  memcpy((void *) &(ip->ip_src), (void *) &saddr, sizeof(saddr));
  memcpy((void *) &(ip->ip_dst), (void *) &daddr, sizeof(daddr));
  ip->ip_sum = click_in_cksum((unsigned char *)ip, sizeof(click_ip));

  // TCP fields
  sport = htons(sport);
  dport = htons(dport);
  memcpy((void *) &(tcp->th_sport), (void *) &sport, sizeof(sport));
  memcpy((void *) &(tcp->th_dport), (void *) &dport, sizeof(dport));
  tcp->th_seq = htonl(seqn);
  tcp->th_ack = htonl(ackn);
  tcp->th_off = 5;
  tcp->th_flags = bits;
  tcp->th_win = htons(32120);
  tcp->th_sum = htons(0);
  tcp->th_urp = htons(0);

  // now calculate tcp header cksum
  unsigned csum = click_in_cksum((unsigned char *)tcp, sizeof(click_tcp));
  tcp->th_sum = click_in_cksum_pseudohdr(csum, ip, sizeof(click_tcp));

  return q;
}


void
TCPIPSend::add_handlers()
{
  add_write_handler("send", send_write_handler, 0);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(TCPIPSend)
