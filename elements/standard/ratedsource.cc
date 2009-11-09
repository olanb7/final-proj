/*
 * ratedsource.{cc,hh} -- generates configurable rated stream of packets.
 * Benjie Chen, Eddie Kohler (based on udpgen.o)
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2008 Regents of the University of California
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
#include "ratedsource.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/router.hh>
#include <click/straccum.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/glue.hh>
CLICK_DECLS

const unsigned RatedSource::NO_LIMIT;

RatedSource::RatedSource()
  : _packet(0), _task(this)
{
}

RatedSource::~RatedSource()
{
}

int
RatedSource::configure(Vector<String> &conf, ErrorHandler *errh)
{
  String data =
    "Random bullshit in a packet, at least 64 bytes long. Well, now it is.";
  unsigned rate = 10;
  int limit = -1;
  int datasize = -1;
  bool active = true, stop = false;

  if (cp_va_kparse(conf, this, errh,
		   "DATA", cpkP, cpString, &data,
		   "RATE", cpkP, cpUnsigned, &rate,
		   "LIMIT", cpkP, cpInteger, &limit,
		   "ACTIVE", cpkP, cpBool, &active,
		   "LENGTH", 0, cpInteger, &datasize,
		   "DATASIZE", 0, cpInteger, &datasize, // deprecated
		   "STOP", 0, cpBool, &stop,
		   cpEnd) < 0)
    return -1;

  _data = data;
  _datasize = datasize;
  _rate.set_rate(rate, errh);
  _limit = (limit >= 0 ? limit : NO_LIMIT);
  _active = active;
  _stop = stop;

  setup_packet();

  return 0;
}

int
RatedSource::initialize(ErrorHandler *errh)
{
  _count = 0;
  if (output_is_push(0))
    ScheduleInfo::initialize_task(this, &_task, errh);
  return 0;
}

void
RatedSource::cleanup(CleanupStage)
{
  if (_packet)
    _packet->kill();
  _packet = 0;
}

bool
RatedSource::run_task(Task *)
{
    if (!_active)
	return false;
    if (_limit != NO_LIMIT && _count >= _limit) {
	if (_stop)
	    router()->please_stop_driver();
	return false;
    }

    Timestamp now = Timestamp::now();
    if (_rate.need_update(now)) {
	_rate.update();
	Packet *p = _packet->clone();
	p->set_timestamp_anno(now);
	output(0).push(p);
	_count++;
	_task.fast_reschedule();
	return true;
    } else {
	_task.fast_reschedule();
	return false;
    }
}

Packet *
RatedSource::pull(int)
{
    if (!_active)
	return 0;
    if (_limit != NO_LIMIT && _count >= _limit) {
	if (_stop)
	    router()->please_stop_driver();
	return 0;
    }

    Timestamp now = Timestamp::now();
    if (_rate.need_update(now)) {
	_rate.update();
	_count++;
	Packet *p = _packet->clone();
	p->set_timestamp_anno(now);
	return p;
    } else
	return 0;
}

void
RatedSource::setup_packet()
{
    if (_packet)
	_packet->kill();

    // note: if you change `headroom', change `click-align'
    unsigned int headroom = 16+20+24;

    if (_datasize < 0)
	_packet = Packet::make(headroom, (unsigned char *) _data.data(), _data.length(), 0);
    else if (_datasize <= _data.length())
	_packet = Packet::make(headroom, (unsigned char *) _data.data(), _datasize, 0);
    else {
	// make up some data to fill extra space
	StringAccum sa;
	while (sa.length() < _datasize)
	    sa << _data;
	_packet = Packet::make(headroom, (unsigned char *) sa.data(), _datasize, 0);
    }
}

String
RatedSource::read_param(Element *e, void *vparam)
{
  RatedSource *rs = (RatedSource *)e;
  switch ((intptr_t)vparam) {
   case 0:			// data
    return rs->_data;
   case 1:			// rate
    return String(rs->_rate.rate());
   case 2:			// limit
    return (rs->_limit != NO_LIMIT ? String(rs->_limit) : String("-1"));
   default:
    return "";
  }
}

int
RatedSource::change_param(const String &s, Element *e, void *vparam,
			  ErrorHandler *errh)
{
  RatedSource *rs = (RatedSource *)e;
  switch ((intptr_t)vparam) {

  case 0:			// data
      rs->_data = s;
      if (rs->_packet)
	  rs->_packet->kill();
      rs->_packet = Packet::make(rs->_data.data(), rs->_data.length());
      break;

   case 1: {			// rate
     unsigned rate;
     if (!cp_integer(s, &rate))
       return errh->error("rate parameter must be integer >= 0");
     if (rate > GapRate::MAX_RATE)
       // report error rather than pin to max
       return errh->error("rate too large; max is %u", GapRate::MAX_RATE);
     rs->_rate.set_rate(rate);
     break;
   }

   case 2: {			// limit
     int limit;
     if (!cp_integer(s, &limit))
       return errh->error("limit parameter must be integer");
     rs->_limit = (limit < 0 ? NO_LIMIT : limit);
     break;
   }

   case 3: {			// active
     bool active;
     if (!cp_bool(s, &active))
       return errh->error("active parameter must be boolean");
     rs->_active = active;
     if (rs->output_is_push(0) && !rs->_task.scheduled() && active) {
       rs->_rate.reset();
       rs->_task.reschedule();
     }
     break;
   }

   case 5: {			// reset
     rs->_count = 0;
     rs->_rate.reset();
     if (rs->output_is_push(0) && !rs->_task.scheduled() && rs->_active)
       rs->_task.reschedule();
     break;
   }

   case 6: {			// datasize
     int datasize;
     if (!cp_integer(s, &datasize))
       return errh->error("length must be integer");
     rs->_datasize = datasize;
     rs->setup_packet();
     break;
   }
  }
  return 0;
}

void
RatedSource::add_handlers()
{
  add_read_handler("data", read_param, (void *)0, Handler::CALM);
  add_write_handler("data", change_param, (void *)0, Handler::RAW);
  add_read_handler("rate", read_param, (void *)1);
  add_write_handler("rate", change_param, (void *)1);
  add_read_handler("limit", read_param, (void *)2, Handler::CALM);
  add_write_handler("limit", change_param, (void *)2);
  add_data_handlers("active", Handler::OP_READ | Handler::CHECKBOX, &_active);
  add_write_handler("active", change_param, (void *)3);
  add_data_handlers("count", Handler::OP_READ, &_count);
  add_write_handler("reset", change_param, (void *)5, Handler::BUTTON);
  add_data_handlers("length", Handler::OP_READ, &_datasize);
  add_write_handler("length", change_param, (void *)6);
  // deprecated
  add_data_handlers("datasize", Handler::OP_READ | Handler::DEPRECATED, &_datasize);
  add_write_handler("datasize", change_param, (void *)6);

  if (output_is_push(0))
    add_task_handlers(&_task);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RatedSource)
