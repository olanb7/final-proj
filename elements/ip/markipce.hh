#ifndef CLICK_MARKIPCE_HH
#define CLICK_MARKIPCE_HH
#include <click/element.hh>
#include <click/atomic.hh>
CLICK_DECLS

/*
=c

MarkIPCE()

=s ip

sets IP packets' ECN field to Congestion Experienced

=d

Expects IP packets as input. Sets each incoming packet's ECN field to
Congestion Experienced (value 3), incrementally recalculates the IP checksum,
and passes the packet to output 0. Non-IP packets, and IP packets whose ECN
field is zero (not ECN-capable), are dropped. */

class MarkIPCE : public Element { public:

  MarkIPCE();
  ~MarkIPCE();

  const char *class_name() const		{ return "MarkIPCE"; }
  const char *port_count() const		{ return PORTS_1_1; }
  const char *processing() const		{ return AGNOSTIC; }

  int initialize(ErrorHandler *);
  void add_handlers();

  inline Packet *smaction(Packet *);
  void push(int, Packet *p);
  Packet *pull(int);

 private:

  atomic_uint32_t _drops;

  static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
