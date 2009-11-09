/*
 * getipaddress.{cc,hh} -- element sets IP destination annotation from
 * packet header
 * Robert Morris
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
#include "getipaddress.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <clicknet/ip.h>
CLICK_DECLS

GetIPAddress::GetIPAddress()
{
}

GetIPAddress::~GetIPAddress()
{
}

int
GetIPAddress::configure(Vector<String> &conf, ErrorHandler *errh)
{
  return cp_va_kparse(conf, this, errh,
		      "OFFSET", cpkP+cpkM, cpUnsigned, &_offset,
		      cpEnd);
}

Packet *
GetIPAddress::simple_action(Packet *p)
{
  p->set_dst_ip_anno(IPAddress(p->data() + _offset));
  return p;
}

CLICK_ENDDECLS
EXPORT_ELEMENT(GetIPAddress)
ELEMENT_MT_SAFE(GetIPAddress)
