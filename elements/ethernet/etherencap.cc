/*
 * etherencap.{cc,hh} -- encapsulates packet in Ethernet header
 *
 * Copyright (c) 2000 Massachusetts Institute of Technology
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
#include "etherencap.hh"
#include <click/etheraddress.hh>
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
CLICK_DECLS

EtherEncap::EtherEncap()
{
}

EtherEncap::~EtherEncap()
{
}

int
EtherEncap::configure(Vector<String> &conf, ErrorHandler *errh)
{
  unsigned etht;
  if (cp_va_kparse(conf, this, errh,
		   "ETHERTYPE", cpkP+cpkM, cpUnsigned, &etht,
		   "SRC", cpkP+cpkM, cpEthernetAddress, &_ethh.ether_shost,
		   "DST", cpkP+cpkM, cpEthernetAddress, &_ethh.ether_dhost,
		   cpEnd) < 0)
    return -1;
  if (etht > 0xFFFF)
    return errh->error("argument 1 (Ethernet encapsulation type) must be <= 0xFFFF");
  _ethh.ether_type = htons(etht);
  return 0;
}

Packet *
EtherEncap::smaction(Packet *p)
{
  if (WritablePacket *q = p->push_mac_header(14)) {
    memcpy(q->data(), &_ethh, 14);
    return q;
  } else
    return 0;
}

void
EtherEncap::push(int, Packet *p)
{
  if (Packet *q = smaction(p))
    output(0).push(q);
}

Packet *
EtherEncap::pull(int)
{
  if (Packet *p = input(0).pull())
    return smaction(p);
  else
    return 0;
}

String
EtherEncap::read_handler(Element *e, void *thunk)
{
  EtherEncap *ee = static_cast<EtherEncap *>(e);
  switch ((intptr_t)thunk) {
   case 0:	return EtherAddress(ee->_ethh.ether_shost).unparse();
   case 1:	return EtherAddress(ee->_ethh.ether_dhost).unparse();
   case 2:	return String(ntohs(ee->_ethh.ether_type));
   default:	return "<error>";
  }
}

void
EtherEncap::add_handlers()
{
  add_read_handler("src", read_handler, (void *)0);
  add_write_handler("src", reconfigure_keyword_handler, "1 SRC");
  add_read_handler("dst", read_handler, (void *)1);
  add_write_handler("dst", reconfigure_keyword_handler, "2 DST");
  add_read_handler("etht", read_handler, (void *)2);
  add_write_handler("etht", reconfigure_keyword_handler, "0 ETHERTYPE");
}

CLICK_ENDDECLS
EXPORT_ELEMENT(EtherEncap)
