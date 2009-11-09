#ifndef CLICK_DECIPTTL_HH
#define CLICK_DECIPTTL_HH
#include <click/element.hh>
#include <click/glue.hh>
#include <click/atomic.hh>
CLICK_DECLS

/*
 * =c
 * DecIPTTL
 * =s ip
 * decrements IP time-to-live, drops dead packets
 * =d
 * Expects IP packet as input.
 * If the ttl is <= 1 (i.e. has expired),
 * DecIPTTL sends the packet to output 1 (or discards it if there is no
 * output 1).
 * Otherwise it decrements the ttl, re-calculates the checksum,
 * and sends the packet to output 0.
 *
 * Ordinarily output 1 is connected to an ICMP error packet generator.
 *
 * =e
 * This is a typical IP input processing sequence:
 *
 *   ... -> CheckIPHeader -> dt::DecIPTTL -> ...
 *   dt[1] -> ICMPError(18.26.4.24, 11, 0) -> ...
 *
 * =a ICMPError, CheckIPHeader
 */

class DecIPTTL : public Element { public:

    DecIPTTL();
    ~DecIPTTL();

    const char *class_name() const		{ return "DecIPTTL"; }
    const char *port_count() const		{ return PORTS_1_1X2; }
    const char *processing() const		{ return PROCESSING_A_AH; }

    void add_handlers();

    Packet *simple_action(Packet *);

  private:

    atomic_uint32_t _drops;

};

CLICK_ENDDECLS
#endif
