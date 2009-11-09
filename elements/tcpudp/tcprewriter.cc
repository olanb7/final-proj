// -*- c-basic-offset: 4 -*-
/*
 * tcprewriter.{cc,hh} -- rewrites packet source and destination
 * Eddie Kohler
 *
 * Copyright (c) 2000 Massachusetts Institute of Technology
 * Copyright (c) 2000 Mazu Networks, Inc.
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
#include "tcprewriter.hh"
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <click/confparse.hh>
#include <click/straccum.hh>
#include <click/error.hh>
#include <click/llrpc.h>
#include <click/router.hh>
CLICK_DECLS

// TCPMapping

TCPRewriter::TCPMapping::TCPMapping(bool dst_anno)
    : Mapping(dst_anno), _trigger(0), _delta(0), _old_delta(0)
{
}

int
TCPRewriter::TCPMapping::update_seqno_delta(tcp_seq_t trigger, int32_t d)
{
    if (SEQ_LEQ(trigger, _trigger) && (_trigger || _delta || _old_delta))
	return -1;
    else {
	_old_delta = _delta;
	_trigger = trigger;
	_delta += d;
	return 0;
    }
}

uint32_t
TCPRewriter::TCPMapping::apply_sack(click_tcp *tcph, int len)
{
    if ((int)(tcph->th_off << 2) < len)
	len = tcph->th_off << 2;
    uint8_t *begin_opt = reinterpret_cast<uint8_t *>(tcph + 1);
    uint8_t *end_opt = reinterpret_cast<uint8_t *>(tcph) + len;
    uint32_t csum_delta = 0;

    uint8_t *opt = begin_opt;
    while (opt < end_opt)
	switch (*opt) {
	  case TCPOPT_EOL:
	    goto done;
	  case TCPOPT_NOP:
	    opt++;
	    break;
	  case TCPOPT_SACK:
	      if (opt + opt[1] > end_opt || (opt[1] % 8) != 2) {
		  goto done;
	      } else {
		  uint8_t *end_sack = opt + opt[1];

		  // develop initial checksum value
		  uint16_t *csum_begin = reinterpret_cast<uint16_t *>(begin_opt + ((opt + 2 - begin_opt) & ~1));
		  for (uint16_t *csum = csum_begin; reinterpret_cast<uint8_t *>(csum) < end_sack; csum++)
		      csum_delta += ~*csum & 0xFFFF;

		  for (opt += 2; opt < end_sack; opt += 8) {
#if HAVE_INDIFFERENT_ALIGNMENT
		      uint32_t *uopt = reinterpret_cast<uint32_t *>(opt);
		      uopt[0] = htonl(new_ack(ntohl(uopt[0])));
		      uopt[1] = htonl(new_ack(ntohl(uopt[1])));
#else
		      uint32_t buf[2];
		      memcpy(&buf[0], opt, 8);
		      buf[0] = htonl(new_ack(ntohl(buf[0])));
		      buf[1] = htonl(new_ack(ntohl(buf[1])));
		      memcpy(opt, &buf[0], 8);
#endif
		  }

		  // finish off csum_delta calculation
		  for (uint16_t *csum = csum_begin; reinterpret_cast<uint8_t *>(csum) < end_sack; csum++)
		      csum_delta += *csum;
		  break;
	      }
	  default:
	    if (opt[1] < 2)
		goto done;
	    opt += opt[1];
	    break;
	}

  done:
    return csum_delta;
}

void
TCPRewriter::TCPMapping::apply(WritablePacket *p)
{
    assert(p->has_network_header());
    click_ip *iph = p->ip_header();

    // IP header
    iph->ip_src = _mapto.saddr();
    iph->ip_dst = _mapto.daddr();
    if (_flags & F_DST_ANNO)
	p->set_dst_ip_anno(_mapto.daddr());

    uint32_t sum = (~iph->ip_sum & 0xFFFF) + _ip_csum_delta;
    sum = (sum & 0xFFFF) + (sum >> 16);
    iph->ip_sum = ~(sum + (sum >> 16));

    mark_used();

    // end if not first fragment
    if (!IP_FIRSTFRAG(iph))
	return;

    // TCP header
    click_tcp *tcph = p->tcp_header();
    tcph->th_sport = _mapto.sport();
    tcph->th_dport = _mapto.dport();

    // update sequence numbers
    uint32_t csum_delta = _udp_csum_delta;

    uint32_t newval = htonl(new_seq(ntohl(tcph->th_seq)));
    if (tcph->th_seq != newval) {
	csum_delta += (~tcph->th_seq >> 16) + (~tcph->th_seq & 0xFFFF)
	    + (newval >> 16) + (newval & 0xFFFF);
	tcph->th_seq = newval;
    }

    newval = htonl(reverse()->new_ack(ntohl(tcph->th_ack)));
    if (tcph->th_ack != newval) {
	csum_delta += (~tcph->th_ack >> 16) + (~tcph->th_ack & 0xFFFF)
	    + (newval >> 16) + (newval & 0xFFFF);
	tcph->th_ack = newval;
    }

    // update SACK sequence numbers
    if ((tcph->th_off > 8
	 || (tcph->th_off == 8
	     && *(reinterpret_cast<const uint32_t *>(tcph + 1)) != htonl(0x0101080A)))
	&& reverse()->have_seqno_delta())
	csum_delta += reverse()->apply_sack(tcph, p->transport_length());

    // update checksum
    uint32_t sum2 = (~tcph->th_sum & 0xFFFF) + csum_delta;
    sum2 = (sum2 & 0xFFFF) + (sum2 >> 16);
    tcph->th_sum = ~(sum2 + (sum2 >> 16));

    // check for session ending flags
    if (tcph->th_flags & TH_RST)
	set_session_over();
    else if (tcph->th_flags & TH_FIN)
	set_session_flow_over();
    else if (tcph->th_flags & TH_SYN)
	clear_session_flow_over();
}

String
TCPRewriter::TCPMapping::s() const
{
  StringAccum sa;
  sa << reverse()->flow_id().reverse() << " => " << flow_id()
     << " seq " << (_delta > 0 ? "+" : "") << _delta
     << " [" + String(output()) + "]";
  return sa.take_string();
}


// TCPRewriter

TCPRewriter::TCPRewriter()
  : _tcp_map(0), _tcp_done(0), _tcp_done_tail(0),
    _tcp_gc_timer(tcp_gc_hook, this),
    _tcp_done_gc_timer(tcp_done_gc_hook, this)
{
}

TCPRewriter::~TCPRewriter()
{
  assert(!_tcp_gc_timer.scheduled() && !_tcp_done_gc_timer.scheduled());
}

void *
TCPRewriter::cast(const char *n)
{
  if (strcmp(n, "IPRw") == 0)
    return (IPRw *)this;
  else if (strcmp(n, "TCPRewriter") == 0)
    return (TCPRewriter *)this;
  else
    return 0;
}

int
TCPRewriter::configure(Vector<String> &conf, ErrorHandler *errh)
{
  int before = errh->nerrors();

  // numbers in seconds
  _tcp_timeout_jiffies = 86400;		// 24 hours
  _tcp_done_timeout_jiffies = 240;	// 4 minutes
  _tcp_gc_interval = 3600;		// 1 hour
  _tcp_done_gc_interval = 10;		// 10 seconds
  _dst_anno = true;

  if (cp_va_kparse_remove_keywords
      (conf, this, errh,
       "REAP_TCP", 0, cpSeconds, &_tcp_gc_interval,
       "REAP_TCP_DONE", 0, cpSeconds, &_tcp_done_gc_interval,
       "TCP_TIMEOUT", 0, cpSeconds, &_tcp_timeout_jiffies,
       "TCP_DONE_TIMEOUT", 0, cpSeconds, &_tcp_done_timeout_jiffies,
       "DST_ANNO", 0, cpBool, &_dst_anno,
       cpEnd) < 0)
    return -1;

  if (conf.size() != ninputs())
      return errh->error("need %d arguments, one per input port", ninputs());

  for (int i = 0; i < conf.size(); i++) {
    InputSpec is;
    if (parse_input_spec(conf[i], is, "input spec " + String(i), errh) >= 0)
      _input_specs.push_back(is);
  }

  // change timeouts into jiffies
  _tcp_timeout_jiffies *= CLICK_HZ;
  _tcp_done_timeout_jiffies *= CLICK_HZ;

  return (errh->nerrors() == before ? 0 : -1);
}

int
TCPRewriter::initialize(ErrorHandler *)
{
  _tcp_gc_timer.initialize(this);
  _tcp_gc_timer.schedule_after_sec(_tcp_gc_interval);
  _tcp_done_gc_timer.initialize(this);
  _tcp_done_gc_timer.schedule_after_sec(_tcp_done_gc_interval);

  _nmapping_failures = 0;
  return 0;
}

void
TCPRewriter::cleanup(CleanupStage)
{
  clear_map(_tcp_map);
  for (int i = 0; i < _input_specs.size(); i++)
    if (_input_specs[i].kind == INPUT_SPEC_PATTERN)
      _input_specs[i].u.pattern.p->unuse();
  _input_specs.clear();
}

int
TCPRewriter::notify_pattern(Pattern *p, ErrorHandler *errh)
{
  if (!p->allow_napt())
    return errh->error("TCPRewriter cannot accept IPAddrRewriter patterns");
  return IPRw::notify_pattern(p, errh);
}

void
TCPRewriter::take_state(Element *e, ErrorHandler *errh)
{
  TCPRewriter *rw = (TCPRewriter *)e->cast("TCPRewriter");
  if (!rw) return;

  if (noutputs() != rw->noutputs()) {
    errh->warning("taking mappings from `%s', although it has %s output ports", rw->declaration().c_str(), (rw->noutputs() > noutputs() ? "more" : "fewer"));
    if (noutputs() < rw->noutputs())
      errh->message("(out of range mappings will be dropped)");
  }

  _tcp_map.swap(rw->_tcp_map);

  // check rw->_all_patterns against our _all_patterns
  Vector<Pattern *> pattern_map;
  for (int i = 0; i < rw->_all_patterns.size(); i++) {
    Pattern *p = rw->_all_patterns[i], *q = 0;
    for (int j = 0; j < _all_patterns.size() && !q; j++)
      if (_all_patterns[j]->can_accept_from(*p))
	q = _all_patterns[j];
    pattern_map.push_back(q);
  }

  take_state_map(_tcp_map, &_tcp_done, &_tcp_done_tail, rw->_all_patterns, pattern_map);
}

void
TCPRewriter::tcp_gc_hook(Timer *timer, void *thunk)
{
  TCPRewriter *rw = (TCPRewriter *)thunk;
  rw->clean_map(rw->_tcp_map, click_jiffies() - rw->_tcp_timeout_jiffies);
  timer->reschedule_after_sec(rw->_tcp_gc_interval);
}

void
TCPRewriter::tcp_done_gc_hook(Timer *timer, void *thunk)
{
  TCPRewriter *rw = (TCPRewriter *)thunk;
  rw->clean_map_free_tracked
    (rw->_tcp_map, rw->_tcp_done, rw->_tcp_done_tail,
     click_jiffies() - rw->_tcp_done_timeout_jiffies);
  timer->reschedule_after_sec(rw->_tcp_done_gc_interval);
}

TCPRewriter::TCPMapping *
TCPRewriter::apply_pattern(Pattern *pattern, int ip_p, const IPFlowID &flow,
			   int fport, int rport)
{
  assert(fport >= 0 && fport < noutputs() && rport >= 0 && rport < noutputs()
	 && ip_p == IP_PROTO_TCP);
  TCPMapping *forward = new TCPMapping(_dst_anno);
  TCPMapping *reverse = new TCPMapping(_dst_anno);

  if (forward && reverse) {
    if (!pattern)
      Mapping::make_pair(ip_p, flow, flow, fport, rport, forward, reverse);
    else if (!pattern->create_mapping(ip_p, flow, fport, rport, forward, reverse, _tcp_map))
      goto failure;

    IPFlowID reverse_flow = forward->flow_id().reverse();
    _tcp_map.set(flow, forward);
    _tcp_map.set(reverse_flow, reverse);
    return forward;
  }

 failure:
  _nmapping_failures++;
  delete forward;
  delete reverse;
  return 0;
}

void
TCPRewriter::push(int port, Packet *p_in)
{
  WritablePacket *p = p_in->uniqueify();
  IPFlowID flow(p);
  click_ip *iph = p->ip_header();
  click_tcp *tcph = p->tcp_header();

  // handle non-first fragments
  if (!IP_FIRSTFRAG(iph) || iph->ip_p != IP_PROTO_TCP) {
    const InputSpec &is = _input_specs[port];
    if (is.kind == INPUT_SPEC_NOCHANGE)
      output(is.u.output).push(p);
    else
      p->kill();
    return;
  }

  TCPMapping *m = static_cast<TCPMapping *>(_tcp_map.get(flow));

  if (!m) {			// create new mapping
    const InputSpec &is = _input_specs[port];
    switch (is.kind) {

     case INPUT_SPEC_NOCHANGE:
      output(is.u.output).push(p);
      return;

     case INPUT_SPEC_DROP:
      break;

     case INPUT_SPEC_KEEP:
     case INPUT_SPEC_PATTERN: {
       Pattern *pat = is.u.pattern.p;
       int fport = is.u.pattern.fport;
       int rport = is.u.pattern.rport;
       m = TCPRewriter::apply_pattern(pat, IP_PROTO_TCP, flow, fport, rport);
       break;
     }

     case INPUT_SPEC_MAPPER: {
       m = static_cast<TCPMapping *>(is.u.mapper->get_map(this, IP_PROTO_TCP, flow, p));
       break;
     }

    }
    if (!m) {
      p->kill();
      return;
    }
  }

  m->apply(p);
  output(m->output()).push(p);

  // add to list for dropping TCP connections faster
  if (!m->free_tracked() && (tcph->th_flags & (TH_FIN | TH_RST))
      && m->session_over())
    m->add_to_free_tracked_tail(_tcp_done, _tcp_done_tail);
}


String
TCPRewriter::dump_mappings_handler(Element *e, void *)
{
  TCPRewriter *rw = (TCPRewriter *)e;
  StringAccum tcps;
  for (Map::iterator iter = rw->_tcp_map.begin(); iter.live(); iter++) {
    TCPMapping *m = static_cast<TCPMapping *>(iter.value());
    if (m->is_primary())
      tcps << m->s() << "\n";
  }
  return tcps.take_string();
}

String
TCPRewriter::dump_patterns_handler(Element *e, void *)
{
    TCPRewriter *rw = (TCPRewriter *)e;
    String s;
    for (int i = 0; i < rw->_input_specs.size(); i++)
	if (rw->_input_specs[i].kind == INPUT_SPEC_PATTERN)
	    s += rw->_input_specs[i].u.pattern.p->unparse() + "\n";
    return s;
}

String
TCPRewriter::dump_nmappings_handler(Element *e, void *thunk)
{
  TCPRewriter *rw = (TCPRewriter *)e;
  if (!thunk)
      return String(rw->_tcp_map.size());
  else
      return String(rw->_nmapping_failures);
}

void
TCPRewriter::add_handlers()
{
  add_read_handler("mappings", dump_mappings_handler, (void *)0);
  add_read_handler("nmappings", dump_nmappings_handler, (void *)0);
  add_read_handler("mapping_failures", dump_nmappings_handler, (void *)1);
  add_read_handler("patterns", dump_patterns_handler, (void *)0);
}

int
TCPRewriter::llrpc(unsigned command, void *data)
{
  if (command == CLICK_LLRPC_IPREWRITER_MAP_TCP) {

    // Data	: unsigned saddr, daddr; unsigned short sport, dport
    // Incoming : the flow ID
    // Outgoing : If there is a mapping for that flow ID, then stores the
    //		  mapping into 'data' and returns zero. Otherwise, returns
    //		  -EAGAIN.

    IPFlowID *val = reinterpret_cast<IPFlowID *>(data);
    TCPMapping *m = get_mapping(IP_PROTO_TCP, *val);
    if (!m)
      return -EAGAIN;
    *val = m->flow_id();
    return 0;

  } else
    return Element::llrpc(command, data);
}


#if 0
void
TCPRewriter::TCPMapping::change_udp_csum_delta(unsigned old_word, unsigned new_word)
{
  const uint16_t *source_words = (const unsigned short *)&old_word;
  const uint16_t *dest_words = (const unsigned short *)&new_word;
  uint32_t delta = _udp_csum_delta;
  for (int i = 0; i < 2; i++) {
    delta += ~source_words[i] & 0xFFFF;
    delta += dest_words[i];
  }
  // why is this required here, but not elsewhere when we do
  // incremental updates?
  if ((int)ntohl(old_word) >= 0 && (int)ntohl(new_word) < 0)
    delta -= htons(1);
  else if ((int)ntohl(old_word) < 0 && (int)ntohl(new_word) >= 0)
    delta += htons(1);
  delta = (delta & 0xFFFF) + (delta >> 16);
  _udp_csum_delta = delta + (delta >> 16);
}
#endif

CLICK_ENDDECLS
ELEMENT_REQUIRES(IPRw IPRewriterPatterns)
EXPORT_ELEMENT(TCPRewriter)
