// -*- mode: c++; c-basic-offset: 4 -*-
/*
 * fromhost.{cc,hh} -- receives packets from Linux
 * Max Poletto, Eddie Kohler
 *
 * Copyright (c) 1999-2000 Massachusetts Institute of Technology
 * Copyright (c) 2000 Mazu Networks, Inc.
 * Copyright (c) 2001-2003 International Computer Science Institute
 * Copyright (c) 2009 Meraki, Inc.
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
#include <click/router.hh>
#include "fromhost.hh"
#include <click/confparse.hh>
#include <click/error.hh>
#include <click/straccum.hh>
#include <click/standard/scheduleinfo.hh>
#include <clicknet/ip6.h>

#include <click/cxxprotect.h>
CLICK_CXX_PROTECT
#include <asm/types.h>
#include <asm/uaccess.h>
#include <linux/ip.h>
#include <linux/inetdevice.h>
#include <linux/if_arp.h>
#include <net/route.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
# include <net/net_namespace.h>
#endif
CLICK_CXX_UNPROTECT
#include <click/cxxunprotect.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 24)
# define netdev_ioctl(cmd, arg)	dev_ioctl(&init_net, (cmd), (arg))
#else
# define netdev_ioctl(cmd, arg)	dev_ioctl((cmd), (arg))
#endif
#ifndef NETDEV_TX_OK
# define NETDEV_TX_OK		0
# define NETDEV_TX_BUSY		1
#endif

extern "C" {
static int fl_open(net_device *);
static int fl_close(net_device *);
static net_device_stats *fl_stats(net_device *);
static void fl_wakeup(Timer *, void *);
}

static AnyDeviceMap fromlinux_map;

void
FromHost::static_initialize()
{
    fromlinux_map.initialize();
}

FromHost::FromHost()
    : _macaddr((const unsigned char *)"\000\001\002\003\004\005"),
      _task(this), _wakeup_timer(fl_wakeup, this),
      _drops(0), _ninvalid(0)
{
    _head = _tail = 0;
    _capacity = 100;
    _q.lgq = 0;
    memset(&_stats, 0, sizeof(_stats));
}

FromHost::~FromHost()
{
}

void *FromHost::cast(const char *name)
{
    if (strcmp(name, "Storage") == 0)
	return (Storage *)this;
    else if (strcmp(name, "FromHost") == 0)
	return (Element *)this;
    else
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
extern "C" {
static void fromhost_inet_setup(struct net_device *dev)
{
    dev->type = ARPHRD_NONE;
    dev->hard_header_len = 0;
    dev->addr_len = 0;
    dev->mtu = 1500;
    dev->flags = IFF_POINTOPOINT | IFF_NOARP | IFF_MULTICAST;
}
}
#endif

net_device *
FromHost::new_device(const char *name)
{
    read_lock(&dev_base_lock);
    void (*setup)(struct net_device *) = (_macaddr ? ether_setup : fromhost_inet_setup);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
    net_device *dev = alloc_netdev(0, name, setup);
#else
    int errcode;
    net_device *dev = dev_alloc(name, &errcode);
#endif
    read_unlock(&dev_base_lock);
    if (!dev)
	return 0;

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 0)
    setup(dev);
#endif
    dev->open = fl_open;
    dev->stop = fl_close;
    dev->hard_start_xmit = fl_tx;
    dev->get_stats = fl_stats;
    dev->mtu = _mtu;
    dev->tx_queue_len = 0;
    return dev;
}

int
FromHost::configure(Vector<String> &conf, ErrorHandler *errh)
{
    String type;
    int mtu = 1500;
    _destaddr = IPAddress();
    _destmask = IPAddress();
    _clear_anno = true;

    if (cp_va_kparse(conf, this, errh,
		     "DEVNAME", cpkP+cpkM, cpString, &_devname,
		     "PREFIX", cpkP, cpIPPrefix, &_destaddr, &_destmask,
		     "TYPE", 0, cpWord, &type,
		     "ETHER", 0, cpEthernetAddress, &_macaddr,
		     "MTU", 0, cpUnsigned, &mtu,
		     "CAPACITY", 0, cpUnsigned, &_capacity,
		     "CLEAR_ANNO", 0, cpBool, &_clear_anno,
		     cpEnd) < 0)
	return -1;

    // check for duplicate element
    if (_devname.length() > IFNAMSIZ - 1)
	return errh->error("device name '%s' too long", _devname.c_str());
    void *&used = router()->force_attachment("FromHost_" + _devname);
    if (used)
	return errh->error("duplicate FromHost for device '%s'", _devname.c_str());
    used = this;

    _mtu = mtu;
    // check for existing device
    _dev = AnyDevice::get_by_name(_devname.c_str());
    if (_dev) {
	if (_dev->open != fl_open) {
	    dev_put(_dev);
	    _dev = 0;
	    return errh->error("device '%s' already exists", _devname.c_str());
	} else {
	    fromlinux_map.insert(this, false);
	    return 0;
	}
    }

    // set type
    if (type == "IP")
	_macaddr = EtherAddress();
    else if (type != "ETHER" && type != "")
	return errh->error("bad TYPE");

    // set up queue
    if (_capacity < 1)
	_capacity = 1;
    if (_capacity > smq_size)
	if (!(_q.lgq = new Packet *[_capacity + 1]))
	    return errh->error("out of memory!");

    // if not found, create new device
    int res;
    _dev = new_device(_devname.c_str());
    if (!_dev)
	return errh->error("out of memory! registering device '%s'", _devname.c_str());
    else if ((res = register_netdev(_dev)) < 0) {
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
	free_netdev(_dev);
#else
	kfree(_dev);
#endif
	_dev = 0;
	return errh->error("error %d registering device '%s'", res, _devname.c_str());
    }

    dev_hold(_dev);
    fromlinux_map.insert(this, false);
    return 0;
}

int
FromHost::set_device_addresses(ErrorHandler *errh)
{
    int res = 0;
    struct ifreq ifr;
    strncpy(ifr.ifr_name, _dev->name, IFNAMSIZ);
    struct sockaddr_in *sin = (struct sockaddr_in *)&ifr.ifr_addr;

    mm_segment_t oldfs = get_fs();
    set_fs(get_ds());

    if (_macaddr) {
	ifr.ifr_hwaddr.sa_family = _dev->type;
	memcpy(ifr.ifr_hwaddr.sa_data, _macaddr.data(), 6);
	if ((res = netdev_ioctl(SIOCSIFHWADDR, &ifr)) < 0)
	    errh->error("error %d setting hardware address for device '%s'", res, _devname.c_str());
    }

    if (_destaddr) {
        sin->sin_family = AF_INET;
        sin->sin_addr = _destaddr;
        if (res >= 0 && (res = devinet_ioctl(SIOCSIFADDR, &ifr)) < 0)
            errh->error("error %d setting address for device '%s'", res, _devname.c_str());

        sin->sin_addr = _destmask;
        if (res >= 0 && (res = devinet_ioctl(SIOCSIFNETMASK, &ifr)) < 0)
            errh->error("error %d setting netmask for device '%s'", res, _devname.c_str());
    }

    set_fs(oldfs);
    return res;
}

static int
dev_updown(net_device *dev, int up, ErrorHandler *errh)
{
    struct ifreq ifr;
    strncpy(ifr.ifr_name, dev->name, IFNAMSIZ);
    uint32_t flags = IFF_UP | IFF_RUNNING;
    int res;

    mm_segment_t oldfs = get_fs();
    set_fs(get_ds());

    (void) netdev_ioctl(SIOCGIFFLAGS, &ifr);
    ifr.ifr_flags = (up > 0 ? ifr.ifr_flags | flags : ifr.ifr_flags & ~flags);
    if ((res = netdev_ioctl(SIOCSIFFLAGS, &ifr)) < 0 && errh)
	errh->error("error %d bringing %s device '%s'", res, (up > 0 ? "up" : "down"), dev->name);

    set_fs(oldfs);
    return res;
}

int
FromHost::initialize(ErrorHandler *errh)
{
    ScheduleInfo::initialize_task(this, &_task, _dev != 0, errh);
    _nonfull_signal = Notifier::downstream_full_signal(this, 0, &_task);
    if (_dev->flags & IFF_UP) {
	_wakeup_timer.initialize(this);
	_wakeup_timer.schedule_now();
	return 0;
    } else if (set_device_addresses(errh) < 0)
	return -1;
    else
	return dev_updown(_dev, 1, errh);
}

void
FromHost::cleanup(CleanupStage)
{
    fromlinux_map.remove(this, false);

    Packet **q = (_capacity <= smq_size ? _q.smq : _q.lgq);
    while (_head != _tail) {
	Packet *p = q[_head];
	p->kill();
	_head = next_i(_head);
    }
    if (_capacity > smq_size)
	delete[] _q.lgq;
    _capacity = 1;
    _head = _tail = 0;

    if (_dev) {
	dev_put(_dev);
	unsigned long lock_flags;
	fromlinux_map.lock(false, lock_flags);
	if (fromlinux_map.lookup(_dev, 0))
	    // do not free device if it is in use
	    _dev = 0;
	fromlinux_map.unlock(false, lock_flags);
	if (_dev) {
	    if (_dev->flags & IFF_UP)
		dev_updown(_dev, -1, 0);
	    unregister_netdev(_dev);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 0)
	    free_netdev(_dev);
#else
	    kfree(_dev);
#endif
	    _dev = 0;
	}
    }
}

/*
 * Device callbacks
 */

extern "C" {
static int
fl_open(net_device *dev)
{
    netif_start_queue(dev);
    return 0;
}

static int
fl_close(net_device *dev)
{
    netif_stop_queue(dev);
    return 0;
}

static void
fl_wakeup(Timer *, void *thunk)
{
    FromHost *fl = (FromHost *)thunk;
    PrefixErrorHandler errh(ErrorHandler::default_handler(), fl->declaration() + ": ");
    net_device *dev = fl->device();

    if (dev->flags & IFF_UP)
	dev_updown(dev, -1, &errh);

    fl->set_device_addresses(&errh);

    dev_updown(dev, 1, &errh);
}

static net_device_stats *
fl_stats(net_device *dev)
{
    net_device_stats *stats = 0;
    unsigned long lock_flags;
    fromlinux_map.lock(false, lock_flags);
    if (FromHost *fl = (FromHost *)fromlinux_map.lookup(dev, 0))
	stats = fl->stats();
    fromlinux_map.unlock(false, lock_flags);
    return stats;
}
}

int
FromHost::fl_tx(struct sk_buff *skb, net_device *dev)
{
    /* 8.May.2003 - Doug and company had crashes with FromHost configurations.
         We eventually figured out this was because fl_tx was called at
         interrupt time -- at bottom-half time, to be exact -- and then pushed
         a packet through the configuration. Whoops: if Click was interrupted,
         and during the bottom-half FromHost emitted a packet into Click,
         DISASTER -- we assume that, when running single-threaded, at most one
         Click thread is active at a time; so there were race conditions,
         particularly with the task list. The solution is a queue in
         FromHost. fl_tx puts a packet onto the queue, a regular Click Task
         takes the packet off the queue. */
    unsigned long lock_flags;
    fromlinux_map.lock(false, lock_flags);
    if (FromHost *fl = (FromHost *)fromlinux_map.lookup(dev, 0)) {
	int r = NETDEV_TX_OK;
	int next = fl->next_i(fl->_tail);
	if (likely(next != fl->_head)) {
	    Packet **q = (fl->_capacity <= smq_size ? fl->_q.smq : fl->_q.lgq);
	    Packet *p = Packet::make(skb);
	    p->set_timestamp_anno(Timestamp::now());
	    if (fl->_clear_anno)
		p->clear_annotations(false);
	    fl->_stats.tx_packets++;
	    fl->_stats.tx_bytes += p->length();
	    fl->_task.reschedule();
	    q[fl->_tail] = p;
	    fl->_tail = next;
	} else {
	    r = NETDEV_TX_BUSY;	// Linux will free the packet.
	    fl->_drops++;
	}
	fromlinux_map.unlock(false, lock_flags);
	return r;
    }
    fromlinux_map.unlock(false, lock_flags);
    return -1;
}

bool
FromHost::run_task(Task *)
{
    if (!_nonfull_signal)
	return false;

    if (likely(!empty())) {
	Packet **q = (_capacity <= smq_size ? _q.smq : _q.lgq);
	Packet *p = q[_head];
	_head = next_i(_head);

	// Convenience for TYPE IP: set the IP header and destination address.
	if (_dev->type == ARPHRD_NONE && p->length() >= 1) {
	    const click_ip *iph = (const click_ip *) p->data();
	    if (iph->ip_v == 4) {
		if (iph->ip_hl >= 5
		    && ntohs(iph->ip_len) >= (iph->ip_hl << 2)
		    && reinterpret_cast<const uint8_t *>(iph) + (iph->ip_hl << 2) <= p->end_data()) {
		    p->set_ip_header(iph, iph->ip_hl << 2);
		    p->set_dst_ip_anno(iph->ip_dst);
		} else
		    goto bad;
	    } else if (iph->ip_v == 6) {
		if (reinterpret_cast<const uint8_t *>(iph) + sizeof(click_ip6) <= p->end_data())
		    p->set_ip6_header(reinterpret_cast<const click_ip6 *>(iph));
		else
		    goto bad;
	    } else {
	      bad:
	        _ninvalid++;
		checked_output_push(1, p);
		goto done;
	    }
	}

	output(0).push(p);

      done:
	if (!empty())
	    _task.fast_reschedule();
	return true;
    } else
	return false;
}

String
FromHost::read_handler(Element *e, void *)
{
    FromHost *fh = (FromHost *) e;
    return String(fh->size());
}

void
FromHost::add_handlers()
{
    add_task_handlers(&_task);
    add_read_handler("length", read_handler, h_length);
    add_data_handlers("capacity", Handler::OP_READ, &_capacity);
    add_data_handlers("drops", Handler::OP_READ, &_drops);
}

ELEMENT_REQUIRES(AnyDevice linuxmodule)
EXPORT_ELEMENT(FromHost)
