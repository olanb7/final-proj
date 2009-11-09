/*
 * pullswitch.{cc,hh} -- element routes packets from one input of several
 * Eddie Kohler
 *
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
#include "pullswitch.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/llrpc.h>
CLICK_DECLS

PullSwitch::PullSwitch()
{
}

PullSwitch::~PullSwitch()
{
}

int
PullSwitch::configure(Vector<String> &conf, ErrorHandler *errh)
{
  _input = 0;
  if (cp_va_kparse(conf, this, errh,
		   "INPUT", cpkP, cpInteger, &_input,
		   cpEnd) < 0)
    return -1;
  if (_input >= ninputs())
    _input = -1;
  return 0;
}

Packet *
PullSwitch::pull(int)
{
  if (_input < 0)
    return 0;
  else
    return input(_input).pull();
}

String
PullSwitch::read_param(Element *e, void *)
{
  PullSwitch *sw = (PullSwitch *)e;
  return String(sw->_input);
}

int
PullSwitch::write_param(const String &s, Element *e, void *, ErrorHandler *errh)
{
  PullSwitch *sw = (PullSwitch *)e;
  if (!cp_integer(s, &sw->_input))
    return errh->error("PullSwitch input must be integer");
  if (sw->_input >= sw->ninputs())
    sw->_input = -1;
  return 0;
}

void
PullSwitch::add_handlers()
{
  add_read_handler("switch", read_param, (void *)0);
  add_write_handler("switch", write_param, (void *)0);
  add_read_handler("config", read_param, (void *)0);
  set_handler_flags("config", 0, Handler::CALM);
}

int
PullSwitch::llrpc(unsigned command, void *data)
{
  if (command == CLICK_LLRPC_SET_SWITCH) {
    int32_t *val = reinterpret_cast<int32_t *>(data);
    _input = (*val >= ninputs() ? -1 : *val);
    return 0;

  } else if (command == CLICK_LLRPC_GET_SWITCH) {
    int32_t *val = reinterpret_cast<int32_t *>(data);
    *val = _input;
    return 0;

  } else
    return Element::llrpc(command, data);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(PullSwitch)
ELEMENT_MT_SAFE(PullSwitch)
