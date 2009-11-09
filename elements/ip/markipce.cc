/*
 * markipce.{cc,hh} -- element marks IP header ECN CE bit
 * Eddie Kohler
 *
 * Copyright (c) 2001 International Computer Science Institute
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
#include "markipce.hh"
#include <clicknet/ip.h>
#include <click/confparse.hh>
#include <click/error.hh>
CLICK_DECLS

MarkIPCE::MarkIPCE()
{
}

MarkIPCE::~MarkIPCE()
{
}

int
MarkIPCE::initialize(ErrorHandler *)
{
  _drops = 0;
  return 0;
}

inline Packet *
MarkIPCE::smaction(Packet *p)
{
  const click_ip *iph = p->ip_header();

  if (!p->has_network_header() || (iph->ip_tos & IP_ECNMASK) == IP_ECN_NOT_ECT) {
    p->kill();
    return 0;
  } else if ((iph->ip_tos & IP_ECNMASK) == IP_ECN_CE)
    return p;
  else {
    WritablePacket *q = p->uniqueify();
    click_ip *q_iph = q->ip_header();

    // incrementally update IP checksum
    // new_sum = ~(~old_sum + ~old_halfword + new_halfword)
    //         = ~(~old_sum + ~old_halfword + (old_halfword + 0x0001))
    //         = ~(~old_sum + ~old_halfword + old_halfword + 0x0001)
    //         = ~(~old_sum + ~0 + 0x0001)
    //         = ~(~old_sum + 0x0001)
    if ((q_iph->ip_tos & IP_ECNMASK) == IP_ECN_ECT2) {
      unsigned sum = (~ntohs(q_iph->ip_sum) & 0xFFFF) + 0x0001;
      q_iph->ip_sum = ~htons(sum + (sum >> 16));
    } else {
      unsigned sum = (~ntohs(q_iph->ip_sum) & 0xFFFF) + 0x0002;
      q_iph->ip_sum = ~htons(sum + (sum >> 16));
    }

    q_iph->ip_tos |= IP_ECN_CE;

    return q;
  }
}

void
MarkIPCE::push(int, Packet *p)
{
  if ((p = smaction(p)) != 0)
    output(0).push(p);
}

Packet *
MarkIPCE::pull(int)
{
  Packet *p = input(0).pull();
  if (p)
    p = smaction(p);
  return p;
}

void
MarkIPCE::add_handlers()
{
    add_data_handlers("drops", Handler::OP_READ, &_drops);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(MarkIPCE)
ELEMENT_MT_SAFE(MarkIPCE)
