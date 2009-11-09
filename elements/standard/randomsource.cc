/*
 * RandomSource.{cc,hh} -- element generates random infinite stream
 * of packets
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
#include "randomsource.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/standard/scheduleinfo.hh>
#include <click/glue.hh>
CLICK_DECLS

RandomSource::RandomSource()
  : _task(this)
{
}

RandomSource::~RandomSource()
{
}

int
RandomSource::configure(Vector<String> &conf, ErrorHandler *errh)
{
  int length;

  if (cp_va_kparse(conf, this, errh,
		   "LENGTH", cpkP+cpkM, cpInteger, &length,
		   cpEnd) < 0)
    return -1;
  if(length < 0 || length >= 64*1024)
    return errh->error("bad length %d", length);
  _length = length;
  return 0;
}

int
RandomSource::initialize(ErrorHandler *errh)
{
    if (output_is_push(0))
	ScheduleInfo::initialize_task(this, &_task, errh);
    return 0;
}

Packet *
RandomSource::make_packet()
{
    WritablePacket *p = Packet::make(36, (const unsigned char*)0, _length, 0);

    int i;
    char *d = (char *) p->data();
    for (i = 0; i < _length; i += sizeof(int))
	*(int*)(d + i) = click_random();
    for( ; i < _length; i++)
	*(d + i) = click_random();

    p->timestamp_anno().set_now();
    return p;
}

bool
RandomSource::run_task(Task *)
{
  Packet *p = make_packet();
  output(0).push(p);
  _task.fast_reschedule();
  return true;
}

Packet *
RandomSource::pull(int)
{
  return make_packet();
}

void
RandomSource::add_handlers()
{
  if (output_is_push(0))
    add_task_handlers(&_task);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(RandomSource)
ELEMENT_MT_SAFE(RandomSource)
