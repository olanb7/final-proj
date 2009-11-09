#ifndef XOKWRITER_HH
#define XOKWRITER_HH
#include <click/element.hh>
#include <click/string.hh>


/*
 * =c
 * xokWriter(devname)
 * =d
 * Write packets to the ethernet via xok ethernet interface. Expects packets
 * that already have an ether header.
 *
 * =a
 * xokReader
 */

class xokWriter : public Element {
  int cardno;

 public:

  xokWriter(int cardno=-1);
  xokWriter(const String &ifname);
  ~xokWriter() {}

  const char *class_name() const		{ return "xokWriter"; }
  const char *port_count() const		{ return PORTS_1_0; }
  const char *processing() const		{ return AGNOSTIC; }

  int configure(Vector<String> &, ErrorHandler *);

  void push(int port, Packet *);

    bool run_task(Task *);

};


#endif XOKWRITER_HH

