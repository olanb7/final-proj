// -*- c-basic-offset: 4 -*-
#ifndef CLICK_FROMDEVICE_HH
#define CLICK_FROMDEVICE_HH

/*
=c

FromDevice(DEVNAME [, I<keywords> PROMISC, BURST, TIMESTAMP...])

=s netdevices

reads packets from network device (Linux kernel)

=d

This manual page describes the Linux kernel module version of the FromDevice
element. For the user-level element, read the FromDevice.u manual page.

Intercepts all packets received by the Linux network interface named DEVNAME
and pushes them out output 0. The packets include the link-level header.
DEVNAME may also be an Ethernet address, in which case FromDevice searches for
a device with that address.

FromDevice receives packets at interrupt time. As this happens, FromDevice
simply stores the packets in an internal queue. Later, in the Click kernel
thread -- that is, not at interrupt time -- FromDevice emits packets from that
queue as it is scheduled by the driver. It emits at most BURST packets per
scheduling; BURST is 8 by default.

Keyword arguments are:

=over 8

=item PROMISC

Boolean.  If true, the device is put into promiscuous mode while FromDevice is
active.  Default is false.

=item BURST

Unsigned integer.  Sets the BURST parameter.

=item TIMESTAMP

Boolean.  If true, then ensure that received packets have correctly-set
timestamp annotations.  Default is true.

=item QUIET

Boolean.  If true, then suppress device up/down messages.  Default is false.

=item ALLOW_NONEXISTENT

Allow nonexistent devices. If true, and no device named DEVNAME exists when
the router is initialized, then FromDevice will report a warning (rather than
an error). Later, while the router is running, if a device named DEVNAME
appears, FromDevice will seamlessly begin outputing its packets. Default is
false.

=item UP_CALL

Write handler.  If supplied, this handler is called when the device or link
comes up.

=item DOWN_CALL

Write handler.  If supplied, this handler is called when the device or link
goes down.

=item ACTIVE

Boolean.  If false, then FromDevice will not accept packets from the attached
device; instead, packets from the device are processed by Linux as usual.
Default is true.

=back

=n

Linux won't see any packets from the device. If you want Linux to process
packets, you should hand them to ToHost.

FromDevice accesses packets the same way Linux does: through interrupts.
This is bad for performance. If you care about performance and have a
polling-capable device, use PollDevice instead.

Linux device drivers, and thus FromDevice, should set packets' timestamp,
packet-type, and device annotations.

=h active read/write

The write handler sets the ACTIVE parameter.  The read handler returns the
ACTIVE parameter if the device is up, or "false" if the device is down.

=a PollDevice, ToDevice, FromHost, ToHost, FromDevice.u */

#include "elements/linuxmodule/anydevice.hh"
#include <click/standard/storage.hh>

class FromDevice : public AnyTaskDevice, public Storage { public:

    FromDevice();
    ~FromDevice();

    static void static_initialize();
    static void static_cleanup();

    const char *class_name() const	{ return "FromDevice"; }
    const char *port_count() const	{ return PORTS_0_1; }
    const char *processing() const	{ return PUSH; }
    void *cast(const char *);

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    void add_handlers();
    void take_state(Element *, ErrorHandler *);

    /* process a packet. return 0 if not wanted after all. */
    int got_skb(struct sk_buff *);

    bool run_task(Task *);
    void reset_counts() {
	_runs = _empty_runs = _pushes = _drops = 0;
    }

  private:

    bool _active;
    unsigned _burst;
    unsigned _drops;

    unsigned _runs;
    unsigned _empty_runs;
    unsigned _pushes;

    enum { QSIZE = 511 };
    Packet *_queue[QSIZE+1];
#if CLICK_DEBUG_SCHEDULING
    struct Schinfo {
	Timestamp enq_time;
	char enq_state;
	char enq_woke_process;
	char enq_task_scheduled;
	uint32_t enq_epoch;
	uint32_t enq_task_epoch;
    };
    Schinfo _schinfo[QSIZE+1];
    void emission_report(int);
#endif

    static String read_handler(Element *, void *);
    static int write_handler(const String &, Element *, void *, ErrorHandler *);

};

#endif
