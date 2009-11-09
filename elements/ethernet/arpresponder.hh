#ifndef CLICK_ARPRESPONDER_HH
#define CLICK_ARPRESPONDER_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/ipaddress.hh>
#include <click/vector.hh>
CLICK_DECLS

/*
 * =c
 *
 * ARPResponder(IP/MASK1 [IP/MASK...] ETH1, IP/MASK2 ETH2, ...)
 *
 * =s arp
 *
 * generates responses to ARP queries
 *
 * =d
 *
 * Input should be ARP request packets, including the Ethernet header.
 * Forwards an ARP reply if we know the answer -- that is, if one of the
 * IPPREFIX arguments matches the requested IP address, then it outputs an ARP
 * reply giving the corresponding ETH address, otherwise the ARP request
 * packet is pushed out of output 1 (if it exists). Could be used for proxy
 * ARP as well as producing replies for a host's own address.
 *
 * The IP/MASK arguments are IP network addresses (IP address/netmask pairs).
 * The netmask can be specified in CIDR form (`C<18.26.7.0/24>') or dotted
 * decimal form (`C<18.26.7.0/255.255.255.0>').
 *
 * ARPResponder sets the device annotations on generated ARP responses to the
 * device annotations from the corresponding queries.
 *
 * =n
 *
 * AddressInfo elements can simplify the arguments to ARPResponder. In
 * particular, if C<NAME> is shorthand for both an IP network address (or IP
 * address) C<IP> and an Ethernet address C<ETH>, then C<ARPResponder(NAME)> is
 * equivalent to C<ARPResponder(IP ETH)>. If C<NAME> is short for both an IP
 * address and an IP network address, then ARPResponder will prefer the IP
 * address. (You can say C<NAME:ipnet> to use the IP network address.)
 *
 * =e
 *
 * Produce ARP replies for the local machine (18.26.4.24)
 * as well as proxy ARP for all machines on net 18.26.7
 * directing their packets to the local machine:
 *
 *   c :: Classifier(12/0806 20/0001, ...);
 *   ar :: ARPResponder(18.26.4.24 18.26.7.0/24 00-00-C0-AE-67-EF);
 *   c[0] -> ar;
 *   ar -> ToDevice(eth0);
 *
 * =a
 *
 * ARPQuerier, ARPFaker, AddressInfo */

class ARPResponder : public Element { public:

  ARPResponder();
  ~ARPResponder();

  const char *class_name() const		{ return "ARPResponder"; }
  const char *port_count() const		{ return PORTS_1_1X2; }
  const char *processing() const		{ return PROCESSING_A_AH; }

  int configure(Vector<String> &, ErrorHandler *);
  int live_reconfigure(Vector<String> &, ErrorHandler *);
  bool can_live_reconfigure() const             { return true; }

  void add_handlers();

  Packet *simple_action(Packet *);

    static Packet *make_response(const uint8_t target_eth[6],
				 const uint8_t target_ip[4],
				 const uint8_t src_eth[6],
				 const uint8_t src_ip[4],
				 Packet *p = 0);

  bool lookup(IPAddress, EtherAddress &) const;

private:

  struct Entry {
    IPAddress dst;
    IPAddress mask;
    EtherAddress ena;
  };
  Vector<Entry> _v;

  void add_map(IPAddress dst, IPAddress mask, EtherAddress);

  static String read_handler(Element *, void *);

};

CLICK_ENDDECLS
#endif
