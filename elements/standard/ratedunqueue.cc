// -*- c-basic-offset: 4 -*-
/*
 * ratedunqueue.{cc,hh} -- element pulls as many packets as possible from
 * its input, pushes them out its output
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
#include "ratedunqueue.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/standard/scheduleinfo.hh>
CLICK_DECLS

RatedUnqueue::RatedUnqueue()
    : _task(this)
{
}

RatedUnqueue::~RatedUnqueue()
{
}

int
RatedUnqueue::configure(Vector<String> &conf, ErrorHandler *errh)
{
    unsigned r;
    CpVaParseCmd cmd = (is_bandwidth() ? cpBandwidth : cpUnsigned);
    if (cp_va_kparse(conf, this, errh,
		     "RATE", cpkP+cpkM, cmd, &r, cpEnd) < 0)
	return -1;
    _rate.set_rate(r, errh);
    return 0;
}

int
RatedUnqueue::initialize(ErrorHandler *errh)
{
    ScheduleInfo::initialize_task(this, &_task, errh);
    _signal = Notifier::upstream_empty_signal(this, 0, &_task);
    return 0;
}

bool
RatedUnqueue::run_task(Task *)
{
    bool worked = false;
    if (_rate.need_update(Timestamp::now())) {
	//_rate.update();  // uncomment this if you want it to run periodically
	if (Packet *p = input(0).pull()) {
	    _rate.update();
	    output(0).push(p);
	    worked = true;
	} else  // no Packet available
	    if (use_signal && !_signal)
		return false;		// without rescheduling
    }
    _task.fast_reschedule();
    return worked;
}


// HANDLERS

String
RatedUnqueue::read_handler(Element *e, void *)
{
    RatedUnqueue *rs = static_cast<RatedUnqueue *>(e);
    if (rs->is_bandwidth())
	return cp_unparse_bandwidth(rs->_rate.rate());
    else
	return String(rs->_rate.rate());
}

void
RatedUnqueue::add_handlers()
{
    add_read_handler("rate", read_handler, 0);
    add_write_handler("rate", reconfigure_keyword_handler, "0 RATE");
    add_task_handlers(&_task);
    add_read_handler("config", read_handler, 0);
    set_handler_flags("config", 0, Handler::CALM);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RatedUnqueue)
ELEMENT_MT_SAFE(RatedUnqueue)
