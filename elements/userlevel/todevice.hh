#ifndef CLICK_TODEVICE_USERLEVEL_HH
#define CLICK_TODEVICE_USERLEVEL_HH
#include <click/element.hh>
#include <click/string.hh>
#include <click/task.hh>
#include <click/timer.hh>
#include <click/notifier.hh>
#include "elements/userlevel/fromdevice.hh"
CLICK_DECLS

/*
 * =title ToDevice.u
 * =c
 * ToDevice(DEVNAME [, I<KEYWORDS>])
 * =s netdevices
 * sends packets to network device (user-level)
 * =d
 *
 * This manual page describes the user-level version of the ToDevice element.
 * For the Linux kernel module element, read the ToDevice(n) manual page.
 *
 * Pulls packets and sends them out the named device using
 * Berkeley Packet Filters (or Linux equivalent).
 *
 * Keyword arguments are:
 *
 * =over 8
 *
 * =item DEBUG
 *
 * Boolean.  If true, print out debug messages.
 *
 * =back
 *
 * This element is only available at user level.
 *
 * =n
 *
 * Packets sent via ToDevice should already have a link-level
 * header prepended. This means that ARP processing,
 * for example, must already have been done.
 *
 * The L<FromDevice(n)> element's OUTBOUND keyword argument determines whether
 * FromDevice receives packets sent by a ToDevice element for the same
 * device.
 *
 * Packets that are written successfully are sent on output 0, if it exists.
 * Packets that fail to be written are pushed out output 1, if it exists.

 * KernelTun lets you send IP packets to the host kernel's IP processing code,
 * sort of like the kernel module's ToHost element.
 *
 * =a
 * FromDevice.u, FromDump, ToDump, KernelTun, ToDevice(n) */

#if defined(__linux__)
# define TODEVICE_LINUX 1
# define TODEVICE_SEND 1
#elif HAVE_PCAP
extern "C" {
# include <pcap.h>
}
# if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__APPLE__) || defined(__NetBSD__)
#  define TODEVICE_BSD_DEV_BPF 1
#  define TODEVICE_WRITE 1
# elif defined(__sun)
#  define TODEVICE_PCAP 1
#  define TODEVICE_WRITE 1
# endif
#endif

class ToDevice : public Element { public:

  ToDevice();
  ~ToDevice();

  const char *class_name() const		{ return "ToDevice"; }
  const char *port_count() const		{ return "1/0-2"; }
  const char *processing() const		{ return "l/h"; }
  const char *flags() const			{ return "S2"; }

  int configure_phase() const { return KernelFilter::CONFIGURE_PHASE_TODEVICE; }
  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  void cleanup(CleanupStage);
  void add_handlers();

  String ifname() const				{ return _ifname; }
  int fd() const				{ return _fd; }

  bool run_task(Task *);
  void selected(int);
  static int write_param(const String &in_s, Element *e, void *vparam, ErrorHandler *errh);
  static String read_param(Element *e, void *thunk);
protected:
  Task _task;
  Timer _timer;
private:

  String _ifname;
  int _fd;
  bool _my_fd;
  NotifierSignal _signal;


  Packet *_q;
public:
  bool _debug;
  bool _backoff;
  int _pulls;
};

CLICK_ENDDECLS
#endif
