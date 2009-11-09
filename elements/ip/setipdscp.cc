/*
 * setipdscp.{cc,hh} -- element sets IP header DSCP field
 * Eddie Kohler
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
#include "setipdscp.hh"
#include <clicknet/ip.h>
#include <click/confparse.hh>
#include <click/error.hh>
CLICK_DECLS

SetIPDSCP::SetIPDSCP()
{
}

SetIPDSCP::~SetIPDSCP()
{
}

int
SetIPDSCP::configure(Vector<String> &conf, ErrorHandler *errh)
{
  unsigned dscp_val;
  if (cp_va_kparse(conf, this, errh,
		   "DSCP", cpkP+cpkM, cpUnsigned, &dscp_val,
		   cpEnd) < 0)
    return -1;
  if (dscp_val > 0x3F)
    return errh->error("diffserv code point out of range");

  // OK: set values
  _dscp = (dscp_val << 2);
  return 0;
}

inline Packet *
SetIPDSCP::smaction(Packet *p_in)
{
  WritablePacket *p = p_in->uniqueify();
  assert(p->has_network_header());
  click_ip *ip = p->ip_header();

  uint16_t old_hw = (reinterpret_cast<uint16_t *>(ip))[0];
  ip->ip_tos = (ip->ip_tos & 0x3) | _dscp;
  uint16_t new_hw = (reinterpret_cast<uint16_t *>(ip))[0];

  // 19.Aug.1999 - incrementally update IP checksum according to RFC1624.
  // new_sum = ~(~old_sum + ~old_halfword + new_halfword)
  uint32_t sum = (~ip->ip_sum & 0xFFFF) + (~old_hw & 0xFFFF) + new_hw;
  sum = (sum & 0xFFFF) + (sum >> 16);
  ip->ip_sum = ~(sum + (sum >> 16));

  return p;
}

void
SetIPDSCP::push(int, Packet *p)
{
  if ((p = smaction(p)) != 0)
    output(0).push(p);
}

Packet *
SetIPDSCP::pull(int)
{
  Packet *p = input(0).pull();
  if (p)
    p = smaction(p);
  return p;
}

void
SetIPDSCP::add_handlers()
{
    add_read_handler("dscp", read_keyword_handler, "0 DSCP", Handler::CALM);
    add_write_handler("dscp", reconfigure_keyword_handler, "0 DSCP");
}

CLICK_ENDDECLS
EXPORT_ELEMENT(SetIPDSCP)
ELEMENT_MT_SAFE(SetIPDSCP)
