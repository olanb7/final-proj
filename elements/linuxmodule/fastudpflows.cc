/*
 * fastudpflows.{cc,hh} -- fast udp flow source, a benchmark tool
 * Benjie Chen
 *
 * Copyright (c) 1999-2001 Massachusetts Institute of Technology
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
#include <clicknet/ip.h>
#include "fastudpflows.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/standard/alignmentinfo.hh>
#ifdef CLICK_LINUXMODULE
# include <net/checksum.h>
#endif

const unsigned FastUDPFlows::NO_LIMIT;

FastUDPFlows::FastUDPFlows()
  : _flows(0)
{
  _rate_limited = true;
  _first = _last = 0;
  _count = 0;
}

FastUDPFlows::~FastUDPFlows()
{
}

int
FastUDPFlows::configure(Vector<String> &conf, ErrorHandler *errh)
{
  _cksum = true;
  _active = true;
  unsigned rate;
  int limit;
  if (cp_va_kparse(conf, this, errh,
		   "RATE", cpkP+cpkM, cpUnsigned, &rate,
		   "LIMIT", cpkP+cpkM, cpInteger, &limit,
		   "LENGTH", cpkP+cpkM, cpUnsigned, &_len,
		   "SRCETH", cpkP+cpkM, cpEthernetAddress, &_ethh.ether_shost,
		   "SRCIP", cpkP+cpkM, cpIPAddress, &_sipaddr,
		   "DSTETH", cpkP+cpkM, cpEthernetAddress, &_ethh.ether_dhost,
		   "DSTIP", cpkP+cpkM, cpIPAddress, &_dipaddr,
		   "FLOWS", cpkP+cpkM, cpUnsigned, &_nflows,
		   "FLOWSIZE", cpkP+cpkM, cpUnsigned, &_flowsize,
		   "CHECKSUM", cpkP, cpBool, &_cksum,
		   "ACTIVE", cpkP, cpBool, &_active,
		   cpEnd) < 0)
    return -1;
  if (_len < 60) {
    click_chatter("warning: packet length < 60, defaulting to 60");
    _len = 60;
  }
  _ethh.ether_type = htons(0x0800);
  if(rate != 0){
    _rate_limited = true;
    _rate.set_rate(rate, errh);
  } else {
    _rate_limited = false;
  }
  _limit = (limit >= 0 ? limit : NO_LIMIT);
  return 0;
}

void
FastUDPFlows::change_ports(int flow)
{
  click_ip *ip = reinterpret_cast<click_ip *>(_flows[flow].packet->data()+14);
  click_udp *udp = reinterpret_cast<click_udp *>(ip + 1);

  udp->uh_sport = (click_random() >> 2) % 0xFFFF;
  udp->uh_dport = (click_random() >> 2) % 0xFFFF;
  udp->uh_sum = 0;
  unsigned short len = _len-14-sizeof(click_ip);
  if (_cksum) {
    unsigned csum = ~click_in_cksum((unsigned char *)udp, len) & 0xFFFF;
    udp->uh_sum = csum_tcpudp_magic(_sipaddr.s_addr, _dipaddr.s_addr,
				    len, IP_PROTO_UDP, csum);
  } else
    udp->uh_sum = 0;
}

Packet *
FastUDPFlows::get_packet()
{
#if 0
  int flow = _last_flow;
  _last_flow = _last_flow+1;
  if (_last_flow >= _nflows) _last_flow = 0;
#else
  int flow = (click_random() >> 2) % _nflows;
#endif

  if (_flows[flow].flow_count == _flowsize) {
    change_ports(flow);
    _flows[flow].flow_count = 0;
  }
  _flows[flow].flow_count++;
  atomic_inc(&(_flows[flow].skb)->users);
  return reinterpret_cast<Packet *>(_flows[flow].skb);
}


int
FastUDPFlows::initialize(ErrorHandler *)
{
  _count = 0;
  _flows = new flow_t[_nflows];

  for (int i=0; i<_nflows; i++) {
    _flows[i].packet = Packet::make(_len);
    memcpy(_flows[i].packet->data(), &_ethh, 14);
    click_ip *ip = reinterpret_cast<click_ip *>(_flows[i].packet->data()+14);
    click_udp *udp = reinterpret_cast<click_udp *>(ip + 1);

    // set up IP header
    ip->ip_v = 4;
    ip->ip_hl = sizeof(click_ip) >> 2;
    ip->ip_len = htons(_len-14);
    ip->ip_id = 0;
    ip->ip_p = IP_PROTO_UDP;
    ip->ip_src = _sipaddr;
    ip->ip_dst = _dipaddr;
    ip->ip_tos = 0;
    ip->ip_off = 0;
    ip->ip_ttl = 250;
    ip->ip_sum = 0;
    ip->ip_sum = click_in_cksum((unsigned char *)ip, sizeof(click_ip));
    _flows[i].packet->set_dst_ip_anno(IPAddress(_dipaddr));
    _flows[i].packet->set_ip_header(ip, sizeof(click_ip));

    // set up UDP header
    udp->uh_sport = (click_random() >> 2) % 0xFFFF;
    udp->uh_dport = (click_random() >> 2) % 0xFFFF;
    udp->uh_sum = 0;
    unsigned short len = _len-14-sizeof(click_ip);
    udp->uh_ulen = htons(len);
    if (_cksum) {
      unsigned csum = ~click_in_cksum((unsigned char *)udp, len) & 0xFFFF;
      udp->uh_sum = csum_tcpudp_magic(_sipaddr.s_addr, _dipaddr.s_addr,
				      len, IP_PROTO_UDP, csum);
    } else
      udp->uh_sum = 0;
    _flows[i].skb = _flows[i].packet->skb();
    _flows[i].flow_count = 0;
  }
  _last_flow = 0;
  return 0;
}

void
FastUDPFlows::cleanup(CleanupStage)
{
  if (_flows) {
    for (int i=0; i<_nflows; i++) {
      _flows[i].packet->kill();
      _flows[i].packet=0;
    }
    delete[] _flows;
    _flows = 0;
  }
}

Packet *
FastUDPFlows::pull(int)
{
  Packet *p = 0;

  if (!_active || (_limit != NO_LIMIT && _count >= _limit)) return 0;

  if(_rate_limited){
    if (_rate.need_update(Timestamp::now())) {
      _rate.update();
      p = get_packet();
    }
  } else
    p = get_packet();

  if(p) {
    _count++;
    if(_count == 1)
      _first = click_jiffies();
    if(_limit != NO_LIMIT && _count >= _limit)
      _last = click_jiffies();
  }

  return(p);
}

void
FastUDPFlows::reset()
{
  _count = 0;
  _first = 0;
  _last = 0;
}

static String
FastUDPFlows_read_count_handler(Element *e, void *)
{
  FastUDPFlows *c = (FastUDPFlows *)e;
  return String(c->count());
}

static String
FastUDPFlows_read_rate_handler(Element *e, void *)
{
  FastUDPFlows *c = (FastUDPFlows *)e;
  if(c->last() != 0){
    int d = c->last() - c->first();
    if (d < 1) d = 1;
    int rate = c->count() * CLICK_HZ / d;
    return String(rate);
  } else {
    return String("0");
  }
}

static int
FastUDPFlows_reset_write_handler
(const String &, Element *e, void *, ErrorHandler *)
{
  FastUDPFlows *c = (FastUDPFlows *)e;
  c->reset();
  return 0;
}

static int
FastUDPFlows_limit_write_handler
(const String &s, Element *e, void *, ErrorHandler *errh)
{
  FastUDPFlows *c = (FastUDPFlows *)e;
  unsigned limit;
  if (!cp_integer(s, &limit))
    return errh->error("limit parameter must be integer >= 0");
  c->_limit = (limit >= 0 ? limit : c->NO_LIMIT);
  return 0;
}

static int
FastUDPFlows_rate_write_handler
(const String &s, Element *e, void *, ErrorHandler *errh)
{
  FastUDPFlows *c = (FastUDPFlows *)e;
  unsigned rate;
  if (!cp_integer(s, &rate))
    return errh->error("rate parameter must be integer >= 0");
  if (rate > GapRate::MAX_RATE)
    // report error rather than pin to max
    return errh->error("rate too large; max is %u", GapRate::MAX_RATE);
  c->_rate.set_rate(rate);
  return 0;
}

static int
FastUDPFlows_active_write_handler
(const String &s, Element *e, void *, ErrorHandler *errh)
{
  FastUDPFlows *c = (FastUDPFlows *)e;
  bool active;
  if (!cp_bool(s, &active))
    return errh->error("active parameter must be boolean");
  c->_active = active;
  if (active) c->reset();
  return 0;
}

void
FastUDPFlows::add_handlers()
{
  add_read_handler("count", FastUDPFlows_read_count_handler, 0);
  add_read_handler("rate", FastUDPFlows_read_rate_handler, 0);
  add_write_handler("rate", FastUDPFlows_rate_write_handler, 0);
  add_write_handler("reset", FastUDPFlows_reset_write_handler, 0, Handler::BUTTON);
  add_write_handler("active", FastUDPFlows_active_write_handler, 0, Handler::CHECKBOX);
  add_write_handler("limit", FastUDPFlows_limit_write_handler, 0);
}

ELEMENT_REQUIRES(linuxmodule)
EXPORT_ELEMENT(FastUDPFlows)
