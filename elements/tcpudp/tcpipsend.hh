#ifndef CLICK_TCPIPSEND_HH
#define CLICK_TCPIPSEND_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <clicknet/tcp.h>
CLICK_DECLS

/*
 * =c
 * TCPIPSend()
 * =s tcp
 * generates TCP/IP packets when requested
 * =d
 *
 * Sends TCP/IP packets when asked to do so. No inputs. One output.
 *
 * =e
 *
 * =h send write-only
 * Expects a string "saddr sport daddr dport seqn ackn bits" with their
 * obvious meaning. Bits is the value of the 6 TCP flags.
 *
 */

class TCPIPSend : public Element {
public:
  TCPIPSend();
  ~TCPIPSend();

  const char *class_name() const	{ return "TCPIPSend"; }
  const char *port_count() const	{ return PORTS_0_1; }
  const char *processing() const	{ return PUSH; }

private:
  void add_handlers();
  static int send_write_handler
    (const String &conf, Element *e, void *, ErrorHandler *errh);
  Packet * make_packet(unsigned int, unsigned int, unsigned short,
                       unsigned short, unsigned, unsigned, unsigned char);
};

CLICK_ENDDECLS
#endif
