// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * todevice.{cc,hh} -- element sends packets to Linux devices.
 * Robert Morris
 * Eddie Kohler: register once per configuration
 * Benjie Chen: polling
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2000 Mazu Networks, Inc.
 * Copyright (c) 2001 International Computer Science Institute
 * Copyright (c) 2005-2007 Regents of the University of California
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
#include <click/glue.hh>
#include "polldevice.hh"
#include "todevice.hh"
#include <click/error.hh>
#include <click/etheraddress.hh>
#include <click/confparse.hh>
#include <click/router.hh>
#include <click/standard/scheduleinfo.hh>

#include <click/cxxprotect.h>
CLICK_CXX_PROTECT
#include <net/pkt_sched.h>
#if __i386__
#include <asm/msr.h>
#endif
CLICK_CXX_UNPROTECT
#include <click/cxxunprotect.h>

/* for watching when devices go offline */
static AnyDeviceMap to_device_map;
static struct notifier_block device_notifier;
extern "C" {
static int device_notifier_hook(struct notifier_block *nb, unsigned long val, void *v);
#if HAVE_CLICK_KERNEL_TX_NOTIFY
static struct notifier_block tx_notifier;
static int registered_tx_notifiers;
static int tx_notifier_hook(struct notifier_block *nb, unsigned long val, void *v);
#endif
}

void
ToDevice::static_initialize()
{
    to_device_map.initialize();
#if HAVE_CLICK_KERNEL_TX_NOTIFY
    tx_notifier.notifier_call = tx_notifier_hook;
    tx_notifier.priority = 1;
    tx_notifier.next = 0;
#endif
    device_notifier.notifier_call = device_notifier_hook;
    device_notifier.priority = 1;
    device_notifier.next = 0;
    register_netdevice_notifier(&device_notifier);

}

void
ToDevice::static_cleanup()
{
    unregister_netdevice_notifier(&device_notifier);
#if HAVE_CLICK_KERNEL_TX_NOTIFY
    if (registered_tx_notifiers)
	unregister_net_tx(&tx_notifier);
#endif
}

inline void
ToDevice::tx_wake_queue(net_device *dev)
{
    //click_chatter("%{element}::%s for dev %s\n", this, __func__, dev->name);
    _task.reschedule();
}

#if HAVE_CLICK_KERNEL_TX_NOTIFY
extern "C" {
static int
tx_notifier_hook(struct notifier_block *nb, unsigned long val, void *v)
{
    struct net_device *dev = (struct net_device *)v;
    if (!dev)
	return 0;
    unsigned long lock_flags;
    to_device_map.lock(false, lock_flags);
    AnyDevice *es[8];
    int nes = to_device_map.lookup_all(dev, true, es, 8);
    for (int i = 0; i < nes; i++)
	((ToDevice *)(es[i]))->tx_wake_queue(dev);
    to_device_map.unlock(false, lock_flags);
    return 0;
}
}
#endif

ToDevice::ToDevice()
    : _q(0), _no_pad(false)
{
}

ToDevice::~ToDevice()
{
}


int
ToDevice::configure(Vector<String> &conf, ErrorHandler *errh)
{
    _burst = 16;
    if (AnyDevice::configure_keywords(conf, errh, false) < 0
	|| cp_va_kparse(conf, this, errh,
			"DEVNAME", cpkP+cpkM, cpString, &_devname,
			"BURST", cpkP, cpUnsigned, &_burst,
			"NO_PAD", 0, cpBool, &_no_pad,
			cpEnd) < 0)
	return -1;
    return find_device(&to_device_map, errh);
}

int
ToDevice::initialize(ErrorHandler *errh)
{
    if (AnyDevice::initialize_keywords(errh) < 0)
	return -1;

#ifndef HAVE_CLICK_KERNEL
    errh->warning("not compiled for a Click kernel");
#endif

    // check for duplicate writers
    if (ifindex() >= 0) {
	void *&used = router()->force_attachment("device_writer_" + String(ifindex()));
	if (used)
	    return errh->error("duplicate writer for device '%s'", _devname.c_str());
	used = this;
    }

#if HAVE_CLICK_KERNEL_TX_NOTIFY
    if (!registered_tx_notifiers) {
	tx_notifier.next = 0;
	register_net_tx(&tx_notifier);
    }
    registered_tx_notifiers++;
#endif

    ScheduleInfo::initialize_task(this, &_task, _dev != 0, errh);
    _signal = Notifier::upstream_empty_signal(this, 0, &_task);

#if HAVE_STRIDE_SCHED
    // user specifies max number of tickets; we start with default
    _max_tickets = _task.tickets();
    _task.set_tickets(Task::DEFAULT_TICKETS);
#endif

    reset_counts();
    return 0;
}

void
ToDevice::reset_counts()
{
  _npackets = 0;

  _busy_returns = 0;
  _dev_idle = 0;
  _hard_start = 0;
  _too_short = 0;
  _runs = 0;
  _drops = 0;
  _holds = 0;
  _pulls = 0;
#if CLICK_DEVICE_STATS
  _activations = 0;
  _time_clean = 0;
  _time_freeskb = 0;
  _time_queue = 0;
  _perfcnt1_pull = 0;
  _perfcnt1_clean = 0;
  _perfcnt1_freeskb = 0;
  _perfcnt1_queue = 0;
  _perfcnt2_pull = 0;
  _perfcnt2_clean = 0;
  _perfcnt2_freeskb = 0;
  _perfcnt2_queue = 0;
#endif
#if CLICK_DEVICE_THESIS_STATS || CLICK_DEVICE_STATS
  _pull_cycles = 0;
#endif
}

void
ToDevice::cleanup(CleanupStage stage)
{
#if HAVE_CLICK_KERNEL_TX_NOTIFY
    if (stage >= CLEANUP_INITIALIZED) {
	registered_tx_notifiers--;
	if (registered_tx_notifiers == 0)
	    unregister_net_tx(&tx_notifier);
    }
#endif
    if (_q)
	_q->kill();
    clear_device(&to_device_map);
}

/*
 * Problem: Linux drivers aren't required to
 * accept a packet even if they've marked themselves
 * as idle. What do we do with a rejected packet?
 */

#if LINUX_VERSION_CODE < 0x020400
# define netif_queue_stopped(dev)	((dev)->tbusy)
# define netif_wake_queue(dev)		mark_bh(NET_BH)
#endif

bool
ToDevice::run_task(Task *)
{
    int busy = 0;
    int sent = 0;

    _runs++;

#if LINUX_VERSION_CODE >= 0x020400
# if HAVE_NETIF_TX_LOCK
    int ok = spin_trylock_bh(&_dev->_xmit_lock);
    if (likely(ok))
	_dev->xmit_lock_owner = smp_processor_id();
    else {
	_task.fast_reschedule();
	return false;
    }
# else
    local_bh_disable();
    if (!spin_trylock(&_dev->xmit_lock)) {
	local_bh_enable();
	_task.fast_reschedule();
	return false;
    }
    _dev->xmit_lock_owner = smp_processor_id();
# endif
#endif

#if CLICK_DEVICE_STATS
    unsigned low00, low10;
    uint64_t time_now;
    SET_STATS(low00, low10, time_now);
#endif

#if HAVE_LINUX_POLLING
    bool is_polling = (_dev->polling > 0);
    struct sk_buff *clean_skbs;
    if (is_polling)
	clean_skbs = _dev->tx_clean(_dev);
    else
	clean_skbs = 0;
#endif

    /* try to send from click */
    while (sent < _burst && (busy = netif_queue_stopped(_dev)) == 0) {
#if CLICK_DEVICE_THESIS_STATS && !CLICK_DEVICE_STATS
	click_cycles_t before_pull_cycles = click_get_cycles();
#endif

	_pulls++;

	Packet *p;
	if ((p = _q)) {
	    _q = 0;
	    if (click_jiffies_less(_q_expiry_j, click_jiffies())) {
		p->kill();
		_drops++;
		p = 0;
	    }
	}
	if (!p && !(p = input(0).pull()))
	    break;

#if CLICK_DEVICE_THESIS_STATS && !CLICK_DEVICE_STATS
	_pull_cycles += click_get_cycles() - before_pull_cycles - CLICK_CYCLE_COMPENSATION;
#endif

	GET_STATS_RESET(low00, low10, time_now,
			_perfcnt1_pull, _perfcnt2_pull, _pull_cycles);

	busy = queue_packet(p);

	GET_STATS_RESET(low00, low10, time_now,
			_perfcnt1_queue, _perfcnt2_queue, _time_queue);

	if (busy)
	    break;
	sent++;
    }

#if HAVE_LINUX_POLLING
    if (is_polling && sent > 0)
	_dev->tx_eob(_dev);

    // If Linux tried to send a packet, but saw tbusy, it will
    // have left it on the queue. It'll just sit there forever
    // (or until Linux sends another packet) unless we poke
    // net_bh(), which calls qdisc_restart(). We are not allowed
    // to call qdisc_restart() ourselves, outside of net_bh().
    if (is_polling && !busy && _dev->qdisc->q.qlen) {
	_dev->tx_eob(_dev);
	netif_wake_queue(_dev);
    }
#endif

#if CLICK_DEVICE_STATS
    if (sent > 0)
	_activations++;
#endif

    if (busy && sent == 0)
	_busy_returns++;

#if HAVE_LINUX_POLLING
    if (is_polling) {
	if (busy && sent == 0) {
	    _dev_idle++;
	    if (_dev_idle == 1024) {
		/* device didn't send anything, ping it */
		_dev->tx_start(_dev);
		_dev_idle = 0;
		_hard_start++;
	    }
	} else
	    _dev_idle = 0;
    }
#endif

#if LINUX_VERSION_CODE >= 0x020400
# if HAVE_NETIF_TX_LOCK
    netif_tx_unlock_bh(_dev);
# else
    _dev->xmit_lock_owner = -1;
    spin_unlock(&_dev->xmit_lock);
    local_bh_enable();
# endif
#endif

    // If we're polling, never go to sleep! We're relying on ToDevice to clean
    // the transmit ring.
    // Otherwise, don't go to sleep if the signal isn't active and
    // we didn't just send any packets
#if HAVE_CLICK_KERNEL_TX_NOTIFY
    bool reschedule = (!busy && (sent > 0 || _signal.active()));
#else
    bool reschedule = (busy || sent > 0 || _signal.active());
#endif

#if HAVE_LINUX_POLLING
    if (is_polling) {
	// 8.Dec.07: Do not recycle skbs until after unlocking the device, to
	// avoid deadlock.  After initial patch by Joonwoo Park.
	if (clean_skbs) {
# if CLICK_DEVICE_STATS
	    if (_activations > 1)
		GET_STATS_RESET(low00, low10, time_now,
				_perfcnt1_clean, _perfcnt2_clean, _time_clean);
# endif
	    skbmgr_recycle_skbs(clean_skbs);
# if CLICK_DEVICE_STATS
	    if (_activations > 1)
		GET_STATS_RESET(low00, low10, time_now,
				_perfcnt1_freeskb, _perfcnt2_freeskb, _time_freeskb);
# endif
	}

	reschedule = true;
	// 9/18/06: Frederic Van Quickenborne reports (1/24/05) that ticket
	// adjustments in FromDevice+ToDevice cause odd behavior.  The ticket
	// adjustments actually don't feel necessary to me in From/ToDevice
	// any more, as described in FromDevice.  So adjusting tickets now
	// only if polling.
	adjust_tickets(sent);
    }
#endif /* HAVE_LINUX_POLLING */

    // 5.Feb.2007: Incorporate a version of a patch from Jason Park.  If the
    // device is "busy", perhaps there is no carrier!  Don't spin on no
    // carrier; instead, rely on Linux's notifer_hook to wake us up again.
    if (busy && sent == 0 && !netif_carrier_ok(_dev))
	reschedule = false;

    if (reschedule)
	_task.fast_reschedule();
    return sent > 0;
}

int
ToDevice::queue_packet(Packet *p)
{
    struct sk_buff *skb1 = p->skb();

    /*
     * Ensure minimum ethernet packet size (14 hdr + 46 data).
     * I can't figure out where Linux does this, so I don't
     * know the correct procedure.
     */
    int need_tail = 60 - p->length();

    if (!_no_pad && need_tail > 0) {
	if (skb_tailroom(skb1) < need_tail) {
	    if (++_too_short == 1)
		printk("<1>ToDevice %s packet too small (len %d, tailroom %d, need %d), had to copy\n", _dev->name, skb1->len, skb_tailroom(skb1), need_tail);
	    struct sk_buff *nskb = skb_copy_expand(skb1, skb_headroom(skb1), skb_tailroom(skb1) + 60 - skb1->len, GFP_ATOMIC);
	    kfree_skb(skb1);
	    if (!nskb)
		return -1;
	    skb1 = nskb;
	}
	// printk("padding %d:%d:%d\n", skb1->truesize, skb1->len, 60-skb1->len);
	skb_put(skb1, need_tail);
    }

    // set the device annotation;
    // apparently some devices in Linux 2.6 require it
    skb1->dev = _dev;

    int ret;
#if HAVE_LINUX_POLLING
    if (_dev->polling > 0)
	ret = _dev->tx_queue(_dev, skb1);
    else
#endif
	{
	    ret = _dev->hard_start_xmit(skb1, _dev);
	    _hard_start++;
	}
    if (ret != 0) {
        _q = p;
	_q_expiry_j = click_jiffies() + queue_timeout;
        if (++_holds == 1)
            printk("<1>ToDevice %s is full, packet delayed\n", _dev->name);
    } else
        _npackets++;
    return ret;
}

void
ToDevice::change_device(net_device *dev)
{
    bool dev_change = _dev != dev;

    if (dev_change)
	_task.strong_unschedule();

    set_device(dev, &to_device_map, true);

    if (dev_change && _dev)
	_task.strong_reschedule();
    else if (_dev && _carrier_ok)
	_task.reschedule();
}

extern "C" {
static int
device_notifier_hook(struct notifier_block *nb, unsigned long flags, void *v)
{
#ifdef NETDEV_GOING_DOWN
    if (flags == NETDEV_GOING_DOWN)
	flags = NETDEV_DOWN;
#endif
    if (flags == NETDEV_DOWN || flags == NETDEV_UP || flags == NETDEV_CHANGE) {
	bool exists = (flags != NETDEV_UP);
	net_device *dev = (net_device *)v;
	unsigned long lock_flags;
	to_device_map.lock(true, lock_flags);
	AnyDevice *es[8];
	int nes = to_device_map.lookup_all(dev, exists, es, 8);
	for (int i = 0; i < nes; i++)
	    ((ToDevice *)(es[i]))->change_device(flags == NETDEV_DOWN ? 0 : dev);
	to_device_map.unlock(true, lock_flags);
    }
    return 0;
}
}

String
ToDevice::read_calls(Element *e, void *)
{
    ToDevice *td = (ToDevice *)e;
    return
	String(td->_holds) + " packets held\n" +
	String(td->_drops) + " packets dropped\n" +
	String(td->_hard_start) + " hard start xmit\n" +
	String(td->_busy_returns) + " device busy returns\n" +
	String(td->_npackets) + " packets sent\n" +
	String(td->_runs) + " calls to run_task()\n" +
	String(td->_pulls) + " pulls\n" +
#if CLICK_DEVICE_STATS
	String(td->_pull_cycles) + " cycles pull\n" +
	String(td->_time_clean) + " cycles clean\n" +
	String(td->_time_freeskb) + " cycles freeskb\n" +
	String(td->_time_queue) + " cycles queue\n" +
	String(td->_perfcnt1_pull) + " perfctr1 pull\n" +
	String(td->_perfcnt1_clean) + " perfctr1 clean\n" +
	String(td->_perfcnt1_freeskb) + " perfctr1 freeskb\n" +
	String(td->_perfcnt1_queue) + " perfctr1 queue\n" +
	String(td->_perfcnt2_pull) + " perfctr2 pull\n" +
	String(td->_perfcnt2_clean) + " perfctr2 clean\n" +
	String(td->_perfcnt2_freeskb) + " perfctr2 freeskb\n" +
	String(td->_perfcnt2_queue) + " perfctr2 queue\n" +
	String(td->_activations) + " transmit activations\n"
#else
	String()
#endif
	;
}

int
ToDevice::write_handler(const String &, Element *e, void *, ErrorHandler *)
{
    ToDevice *td = (ToDevice *)e;
    td->reset_counts();
    return 0;
}

void
ToDevice::add_handlers()
{
    add_read_handler("calls", read_calls, 0);
    add_data_handlers("count", Handler::OP_READ, &_npackets);
    add_data_handlers("drops", Handler::OP_READ, &_drops);
    add_data_handlers("holds", Handler::OP_READ, &_holds);
    add_data_handlers("packets", Handler::OP_READ | Handler::DEPRECATED, &_npackets);
#if CLICK_DEVICE_THESIS_STATS || CLICK_DEVICE_STATS
    add_read_handler("pull_cycles", Handler::OP_READ, &_pull_cycles);
#endif
#if CLICK_DEVICE_STATS
    add_read_handler("enqueue_cycles", Handler::OP_READ, &_time_queue);
    add_read_handler("clean_dma_cycles", Handler::OP_READ, &_time_clean);
#endif
    add_write_handler("reset_counts", write_handler, 0, Handler::BUTTON);
    add_task_handlers(&_task);
}

ELEMENT_REQUIRES(AnyDevice linuxmodule)
EXPORT_ELEMENT(ToDevice)
