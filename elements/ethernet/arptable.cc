/*
 * arptable.{cc,hh} -- ARP resolver element
 * Eddie Kohler
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2005 Regents of the University of California
 * Copyright (c) 2008 Meraki, Inc.
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
#include "arpquerier.hh"
#include <clicknet/ether.h>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
#include <click/confparse.hh>
#include <click/bitvector.hh>
#include <click/straccum.hh>
#include <click/router.hh>
#include <click/error.hh>
#include <click/glue.hh>
CLICK_DECLS

ARPTable::ARPTable()
    : _entry_capacity(0), _packet_capacity(2048), _expire_timer(this)
{
    _entry_count = _packet_count = _drops = 0;
}

ARPTable::~ARPTable()
{
}

int
ARPTable::configure(Vector<String> &conf, ErrorHandler *errh)
{
    Timestamp timeout(300);
    if (cp_va_kparse(conf, this, errh,
		     "CAPACITY", 0, cpUnsigned, &_packet_capacity,
		     "ENTRY_CAPACITY", 0, cpUnsigned, &_entry_capacity,
		     "TIMEOUT", 0, cpTimestamp, &timeout,
		     cpEnd) < 0)
	return -1;
    set_timeout(timeout);
    if (_timeout_j) {
	_expire_timer.initialize(this);
	_expire_timer.schedule_after_sec(_timeout_j / CLICK_HZ);
    }
    return 0;
}

void
ARPTable::cleanup(CleanupStage)
{
    clear();
}

void
ARPTable::clear()
{
    // Walk the arp cache table and free any stored packets and arp entries.
    for (Table::iterator it = _table.begin(); it; ) {
	ARPEntry *ae = _table.erase(it);
	while (Packet *p = ae->_head) {
	    ae->_head = p->next();
	    p->kill();
	    ++_drops;
	}
	_alloc.deallocate(ae);
    }
    _entry_count = _packet_count = 0;
    _age.__clear();
}

void
ARPTable::take_state(Element *e, ErrorHandler *errh)
{
    ARPTable *arpt = (ARPTable *)e->cast("ARPTable");
    if (!arpt)
	return;
    if (_table.size() > 0) {
	errh->error("late take_state");
	return;
    }

    _table.swap(arpt->_table);
    _age.swap(arpt->_age);
    _entry_count = arpt->_entry_count;
    _packet_count = arpt->_packet_count;
    _drops = arpt->_drops;
    _alloc.swap(arpt->_alloc);

    arpt->_entry_count = 0;
    arpt->_packet_count = 0;
}

void
ARPTable::slim()
{
    click_jiffies_t now = click_jiffies();
    ARPEntry *ae;

    // Delete old entries.
    while ((ae = _age.front())
	   && (ae->expired(now, _timeout_j)
	       || (_entry_capacity && _entry_count > _entry_capacity))) {
	_table.erase(ae->_ip);
	_age.pop_front();

	while (Packet *p = ae->_head) {
	    ae->_head = p->next();
	    p->kill();
	    --_packet_count;
	    ++_drops;
	}

	_alloc.deallocate(ae);
	--_entry_count;
    }

    // Mark entries for polling, and delete packets to make space.
    while (_packet_capacity && _packet_count > _packet_capacity) {
	while (ae->_head && _packet_count > _packet_capacity) {
	    Packet *p = ae->_head;
	    if (!(ae->_head = p->next()))
		ae->_tail = 0;
	    p->kill();
	    --_packet_count;
	    ++_drops;
	}
	ae = ae->_age_link.next();
    }
}

void
ARPTable::run_timer(Timer *timer)
{
    // Expire any old entries, and make sure there's room for at least one
    // packet.
    _lock.acquire_write();
    slim();
    _lock.release_write();
    if (_timeout_j)
	timer->schedule_after_sec(_timeout_j / CLICK_HZ + 1);
}

ARPTable::ARPEntry *
ARPTable::ensure(IPAddress ip)
{
    _lock.acquire_write();
    Table::iterator it = _table.find(ip);
    if (!it) {
	void *x = _alloc.allocate();
	if (!x) {
	    _lock.release_write();
	    return 0;
	}

	++_entry_count;
	if (_entry_capacity && _entry_count > _entry_capacity)
	    slim();

	ARPEntry *ae = new(x) ARPEntry(ip);
	ae->_live_at_j = click_jiffies();
	ae->_polled_at_j = ae->_live_at_j - CLICK_HZ;
	_table.set(it, ae);

	_age.push_back(ae);
    }
    return it.get();
}

int
ARPTable::insert(IPAddress ip, const EtherAddress &eth, Packet **head)
{
    ARPEntry *ae = ensure(ip);
    if (!ae)
	return -ENOMEM;

    ae->_eth = eth;
    ae->_unicast = !eth.is_broadcast();

    ae->_live_at_j = click_jiffies();
    ae->_polled_at_j = ae->_live_at_j - CLICK_HZ;

    if (ae->_age_link.next()) {
	_age.erase(ae);
	_age.push_back(ae);
    }

    if (head) {
	*head = ae->_head;
	ae->_head = ae->_tail = 0;
	for (Packet *p = *head; p; p = p->next())
	    --_packet_count;
    }

    _table.balance();
    _lock.release_write();
    return 0;
}

int
ARPTable::append_query(IPAddress ip, Packet *p)
{
    ARPEntry *ae = ensure(ip);
    if (!ae)
	return -ENOMEM;

    click_jiffies_t now = click_jiffies();
    if (ae->unicast(now, _timeout_j)) {
	_lock.release_write();
	return -EAGAIN;
    }

    // Since we're still trying to send to this address, keep the entry just
    // this side of expiring.  This fixes a bug reported 5 Nov 2009 by Seiichi
    // Tetsukawa, and verified via testie, where the slim() below could delete
    // the "ae" ARPEntry when "ae" was the oldest entry in the system.
    if (_timeout_j) {
	click_jiffies_t live_at_j_min = now - _timeout_j;
	if (click_jiffies_less(ae->_live_at_j, live_at_j_min)) {
	    ae->_live_at_j = live_at_j_min;
	    // Now move "ae" to the right position in the list by walking
	    // forward over other elements (potentially expensive?).
	    ARPEntry *ae_next = ae->_age_link.next(), *next = ae_next;
	    while (next && click_jiffies_less(next->_live_at_j, ae->_live_at_j))
		next = next->_age_link.next();
	    if (ae_next != next) {
		_age.erase(ae);
		_age.insert(next /* might be null */, ae);
	    }
	}
    }

    ++_packet_count;
    if (_packet_capacity && _packet_count > _packet_capacity)
	slim();

    if (ae->_tail)
	ae->_tail->set_next(p);
    else
	ae->_head = p;
    ae->_tail = p;
    p->set_next(0);

    int r;
    if (!click_jiffies_less(now, ae->_polled_at_j + CLICK_HZ / 10)) {
	ae->_polled_at_j = now;
	r = 1;
    } else
	r = 0;

    _table.balance();
    _lock.release_write();
    return r;
}

IPAddress
ARPTable::reverse_lookup(const EtherAddress &eth)
{
    _lock.acquire_read();

    IPAddress ip;
    for (Table::iterator it = _table.begin(); it; ++it)
	if (it->_eth == eth) {
	    ip = it->_ip;
	    break;
	}

    _lock.release_read();
    return ip;
}

String
ARPTable::read_handler(Element *e, void *user_data)
{
    ARPTable *arpt = (ARPTable *) e;
    StringAccum sa;
    click_jiffies_t now = click_jiffies();
    switch (reinterpret_cast<uintptr_t>(user_data)) {
    case h_table:
	for (ARPEntry *ae = arpt->_age.front(); ae; ae = ae->_age_link.next()) {
	    int ok = ae->unicast(now, arpt->_timeout_j);
	    sa << ae->_ip << ' ' << ok << ' ' << ae->_eth << ' '
	       << Timestamp::make_jiffies(now - ae->_live_at_j) << '\n';
	}
	break;
    }
    return sa.take_string();
}

int
ARPTable::write_handler(const String &str, Element *e, void *user_data, ErrorHandler *errh)
{
    ARPTable *arpt = (ARPTable *) e;
    switch (reinterpret_cast<uintptr_t>(user_data)) {
      case h_insert: {
	  IPAddress ip;
	  EtherAddress eth;
	  if (cp_va_space_kparse(str, arpt, errh,
				 "IP", cpkP+cpkM, cpIPAddress, &ip,
				 "ETH", cpkP+cpkM, cpEtherAddress, &eth,
				 cpEnd) < 0)
	      return -1;
	  arpt->insert(ip, eth);
	  return 0;
      }
      case h_delete: {
	  IPAddress ip;
	  if (cp_va_space_kparse(str, arpt, errh,
				 "IP", cpkP+cpkM, cpIPAddress, &ip,
				 cpEnd) < 0)
	      return -1;
	  arpt->insert(ip, EtherAddress::make_broadcast()); // XXX?
	  return 0;
      }
      case h_clear:
	arpt->clear();
	return 0;
      default:
	return -1;
    }
}

void
ARPTable::add_handlers()
{
    add_read_handler("table", read_handler, h_table);
    add_data_handlers("drops", Handler::OP_READ, &_drops);
    add_data_handlers("count", Handler::OP_READ, &_entry_count);
    add_data_handlers("length", Handler::OP_READ, &_packet_count);
    add_write_handler("insert", write_handler, h_insert);
    add_write_handler("delete", write_handler, h_delete);
    add_write_handler("clear", write_handler, h_clear);
}

CLICK_ENDDECLS
EXPORT_ELEMENT(ARPTable)
ELEMENT_MT_SAFE(ARPTable)
