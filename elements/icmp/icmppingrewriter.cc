/* -*- c-basic-offset: 2 -*- */
/*
 * icmppingrewriter.{cc,hh} -- rewrites ICMP echoes and replies
 * Eddie Kohler
 *
 * Copyright (c) 2000-2001 Mazu Networks, Inc.
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
#include "icmppingrewriter.hh"
#include <clicknet/ip.h>
#include <clicknet/icmp.h>
#include <click/confparse.hh>
#include <click/straccum.hh>
#include <click/error.hh>
#include <click/router.hh>
CLICK_DECLS

ICMPPingRewriter::ICMPPingRewriter()
  : _request_map(0), _reply_map(0), _timer(this)
{
}

ICMPPingRewriter::~ICMPPingRewriter()
{
  assert(!_timer.scheduled());
}

int
ICMPPingRewriter::configure(Vector<String> &conf, ErrorHandler *errh)
{
  int ok = 0;

  _dst_anno = true;
  String srcarg, dstarg;
  _identifier = 0;

  if (cp_va_kparse(conf, this, errh,
		   "SRC", cpkP+cpkM, cpArgument, &srcarg,
		   "DST", cpkP+cpkM, cpArgument, &dstarg,
		   "DST_ANNO", 0, cpBool, &_dst_anno,
		   cpEnd) < 0)
    return -1;

  if (srcarg == "-")
    _new_src = IPAddress();
  else if (!cp_ip_address(srcarg, &_new_src, this))
    ok = errh->error("type mismatch: SRC requires IP address");

  if (dstarg == "-")
    _new_dst = IPAddress();
  else if (!cp_ip_address(dstarg, &_new_dst, this))
    ok = errh->error("type mismatch: DST requires IP address");

  return ok;
}

int
ICMPPingRewriter::initialize(ErrorHandler *)
{
  _timer.initialize(this);
  _timer.schedule_after_msec(GC_INTERVAL_SEC * 1000);
  return 0;
}

void
ICMPPingRewriter::cleanup(CleanupStage)
{
  for (Map::iterator iter = _request_map.begin(); iter.live(); iter++) {
    Mapping *m = iter.value();
    delete m->reverse();
    delete m;
  }
  _request_map.clear();
  _reply_map.clear();
}

/* XXX
void
ICMPPingRewriter::take_state(Element *e, ErrorHandler *errh)
{
  ICMPPingRewriter *rw = (ICMPPingRewriter *)e->cast("ICMPPingRewriter");
  if (!rw) return;

  if (noutputs() != rw->noutputs()) {
    errh->warning("taking mappings from `%s', although it has\n%s output ports", rw->declaration().c_str(), (rw->noutputs() > noutputs() ? "more" : "fewer"));
    if (noutputs() < rw->noutputs())
      errh->message("(out of range mappings will be dropped)");
  }

  _tcp_map.swap(rw->_tcp_map);
  _udp_map.swap(rw->_udp_map);

  // check rw->_all_patterns against our _all_patterns
  Vector<Pattern *> pattern_map;
  for (int i = 0; i < rw->_all_patterns.size(); i++) {
    Pattern *p = rw->_all_patterns[i], *q = 0;
    for (int j = 0; j < _all_patterns.size() && !q; j++)
      if (_all_patterns[j]->can_accept_from(*p))
	q = _all_patterns[j];
    pattern_map.push_back(q);
  }

  take_state_map(_tcp_map, rw->_all_patterns, pattern_map);
  take_state_map(_udp_map, rw->_all_patterns, pattern_map);
}
*/

ICMPPingRewriter::Mapping::Mapping(bool dst_anno)
  : _used(false), _dst_anno(dst_anno)
{
}

void
ICMPPingRewriter::Mapping::initialize(const IPFlowID &in, const IPFlowID &out,
				      bool is_reverse, Mapping *reverse)
{
  // set fields
  _mapto = out;
  _is_reverse = is_reverse;
  _reverse = reverse;

  // set checksum deltas
  const unsigned short *source_words = (const unsigned short *)&in;
  const unsigned short *dest_words = (const unsigned short *)&_mapto;
  unsigned delta = 0;
  for (int i = 0; i < 4; i++) {
    delta += ~source_words[i] & 0xFFFF;
    delta += dest_words[i];
  }
  delta = (delta & 0xFFFF) + (delta >> 16);
  _ip_csum_delta = delta + (delta >> 16);

  delta = ~source_words[4] & 0xFFFF;
  delta += dest_words[4];
  delta = (delta & 0xFFFF) + (delta >> 16);
  _icmp_csum_delta = delta + (delta >> 16);
}

void
ICMPPingRewriter::Mapping::make_pair(const IPFlowID &inf, const IPFlowID &outf,
				 Mapping *in_map, Mapping *out_map)
{
  in_map->initialize(inf, outf, false, out_map);
  out_map->initialize(outf.reverse(), inf.reverse(), true, in_map);
}

void
ICMPPingRewriter::Mapping::apply(WritablePacket *p)
{
  assert(p->has_network_header());
  click_ip *iph = p->ip_header();

  // IP header
  iph->ip_src = _mapto.saddr();
  iph->ip_dst = _mapto.daddr();
  if (_dst_anno)
    p->set_dst_ip_anno(_mapto.daddr());

  unsigned sum = (~iph->ip_sum & 0xFFFF) + _ip_csum_delta;
  sum = (sum & 0xFFFF) + (sum >> 16);
  iph->ip_sum = ~(sum + (sum >> 16));

  // ICMP header
  click_icmp_echo *icmph = reinterpret_cast<click_icmp_echo *>(p->icmp_header());
  icmph->icmp_identifier = _mapto.sport();

  unsigned sum2 = (~icmph->icmp_cksum & 0xFFFF) + _icmp_csum_delta;
  sum2 = (sum2 & 0xFFFF) + (sum2 >> 16);
  icmph->icmp_cksum = ~(sum2 + (sum2 >> 16));

  // The above incremental algorithm is sufficient for IP headers, because it
  // is always the case that IP headers have at least one nonzero byte (and
  // thus the one's-complement sum of their 16-bit words cannot be +0, so the
  // checksum field cannot be -0). However, it is not enough for ICMP, because
  // an ICMP header MAY have all zero bytes (and thus the one's-complement sum
  // of its 16-bit words MIGHT be +0, and the checksum field MIGHT be -0).
  // Therefore, if the resulting icmp_cksum is +0, we do a full checksum to
  // verify.
  if (!icmph->icmp_cksum)
    icmph->icmp_cksum = click_in_cksum((const unsigned char *)icmph, p->length() - p->transport_header_offset());

  mark_used();
}

String
ICMPPingRewriter::Mapping::s() const
{
  StringAccum sa;
  IPFlowID src_flow = reverse()->flow_id().reverse();
  sa << "(" << src_flow.saddr() << ", " << src_flow.daddr() << ", "
     << ntohs(src_flow.sport()) << ") => (" << _mapto.saddr() << ", "
     << _mapto.daddr() << ", " << ntohs(_mapto.sport()) << ")";
  return sa.take_string();
}

void
ICMPPingRewriter::run_timer(Timer *)
{
  Vector<Mapping *> to_free;

  for (Map::iterator iter = _request_map.begin(); iter.live(); iter++) {
    Mapping *m = iter.value();
    if (!m->used() && !m->reverse()->used())
      to_free.push_back(m);
    else
      m->clear_used();
  }

  for (int i = 0; i < to_free.size(); i++) {
    _request_map.erase(to_free[i]->reverse()->flow_id().reverse());
    _reply_map.erase(to_free[i]->flow_id().reverse());
    delete to_free[i]->reverse();
    delete to_free[i];
  }

  _timer.schedule_after_msec(GC_INTERVAL_SEC * 1000);
}

ICMPPingRewriter::Mapping *
ICMPPingRewriter::apply_pattern(const IPFlowID &flow)
{
  Mapping *forward = new Mapping(_dst_anno);
  Mapping *reverse = new Mapping(_dst_anno);

  if (forward && reverse) {
    IPFlowID new_flow(_new_src, _identifier, _new_dst, _identifier);
    if (!_new_src)
      new_flow.set_saddr(flow.saddr());
    if (!_new_dst)
      new_flow.set_daddr(flow.daddr());
    Mapping::make_pair(flow, new_flow, forward, reverse);
    _identifier++;

    _request_map.set(flow, forward);
    _reply_map.set(new_flow.reverse(), reverse);
    return forward;
  }

  delete forward;
  delete reverse;
  return 0;
}

ICMPPingRewriter::Mapping *
ICMPPingRewriter::get_mapping(bool is_request, const IPFlowID &flow) const
{
  const Map *map = (is_request ? &_request_map : &_reply_map);
  return (*map)[flow];
}

void
ICMPPingRewriter::push(int port, Packet *p_in)
{
  WritablePacket *p = p_in->uniqueify();
  click_ip *iph = p->ip_header();
  assert(iph->ip_p == IP_PROTO_ICMP);

  click_icmp_echo *icmph = reinterpret_cast<click_icmp_echo *>(p->icmp_header());

  Map *map;
  if (icmph->icmp_type == ICMP_ECHO)
    map = &_request_map;
  else if (icmph->icmp_type == ICMP_ECHOREPLY)
    map = &_reply_map;
  else {
    click_chatter("ICMPPingRewriter got non-request, non-reply");
    p->kill();
    return;
  }

  IPFlowID flow(iph->ip_src, icmph->icmp_identifier, iph->ip_dst, icmph->icmp_identifier);
  Mapping *m = map->get(flow);
  if (!m) {
    if (port == 0 && icmph->icmp_type == ICMP_ECHO) {
      // create new mapping
      m = apply_pattern(flow);
    } else if (port == 0) {
      // pass through unchanged
      output(noutputs() - 1).push(p);
      return;
    }
    if (!m) {
      p->kill();
      return;
    }
  }

  m->apply(p);
  if (icmph->icmp_type == ICMP_ECHOREPLY && noutputs() == 2)
    output(1).push(p);
  else
    output(0).push(p);
}


String
ICMPPingRewriter::dump_mappings_handler(Element *e, void *)
{
  ICMPPingRewriter *rw = (ICMPPingRewriter *)e;

  StringAccum sa;
  for (Map::iterator iter = rw->_request_map.begin(); iter.live(); iter++) {
    Mapping *m = iter.value();
    sa << m->s() << "\n";
  }
  return sa.take_string();
}

void
ICMPPingRewriter::add_handlers()
{
  add_read_handler("mappings", dump_mappings_handler, (void *)0);
}

EXPORT_ELEMENT(ICMPPingRewriter)
CLICK_ENDDECLS
