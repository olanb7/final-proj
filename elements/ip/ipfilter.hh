#ifndef CLICK_IPFILTER_HH
#define CLICK_IPFILTER_HH
#include "elements/standard/classifier.hh"
#include <click/hashmap.hh>
CLICK_DECLS

/*
=c

IPFilter(ACTION_1 PATTERN_1, ..., ACTION_N PATTERN_N)

=s ip

filters IP packets by contents

=d

Filters IP packets. IPFilter can have an arbitrary number of filters, which
are ACTION-PATTERN pairs. The ACTIONs describe what to do with packets,
while the PATTERNs are tcpdump(1)-like patterns; see IPClassifier(n) for a
description of their syntax. Packets are tested against the filters in
order, and are processed according to the ACTION in the first filter that
matched.

Each ACTION is either a port number, which specifies that the packet should be
sent out on that port; 'C<allow>', which is equivalent to 'C<0>'; or 'C<drop>'
, which means drop the packet. You can also say 'C<deny>' instead of
'C<drop>', but see the compatibility note below.

The IPFilter element has an arbitrary number of outputs. Input packets must
have their IP header annotation set; CheckIPHeader and MarkIPHeader do
this.

=n

Every IPFilter element has an equivalent corresponding IPClassifier element
and vice versa. Use the element whose syntax is more convenient for your
needs.

B<Compatibility note>: 'C<deny>' formerly meant 'C<1>' if the element had at
least two outputs and 'C<drop>' if it did not. We decided this was
error-prone; now it just means 'C<drop>'. For now, however, 'C<deny>' will
print a warning if used on an element with more than one output.

=e

This large IPFilter implements the incoming packet filtering rules for the
"Interior router" described on pp691-692 of I<Building Internet Firewalls,
Second Edition> (Elizabeth D. Zwicky, Simon Cooper, and D. Brent Chapman,
O'Reilly and Associates, 2000). The captialized words (C<INTERNALNET>,
C<BASTION>, etc.) are addresses that have been registered with
AddressInfo(n). The rule FTP-7 has a port range that cannot be implemented
with IPFilter.

  IPFilter(// Spoof-1:
           deny src INTERNALNET,
           // HTTP-2:
           allow src BASTION && dst INTERNALNET
              && tcp && src port www && dst port > 1023 && ack,
           // Telnet-2:
           allow dst INTERNALNET
              && tcp && src port 23 && dst port > 1023 && ack,
           // SSH-2:
           allow dst INTERNALNET && tcp && src port 22 && ack,
           // SSH-3:
           allow dst INTERNALNET && tcp && dst port 22,
           // FTP-2:
           allow dst INTERNALNET
              && tcp && src port 21 && dst port > 1023 && ack,
           // FTP-4:
           allow dst INTERNALNET
              && tcp && src port > 1023 && dst port > 1023 && ack,
           // FTP-6:
           allow src BASTION && dst INTERNALNET
              && tcp && src port 21 && dst port > 1023 && ack,
           // FTP-7 omitted
           // FTP-8:
           allow src BASTION && dst INTERNALNET
              && tcp && src port > 1023 && dst port > 1023,
           // SMTP-2:
           allow src BASTION && dst INTERNAL_SMTP
              && tcp && src port 25 && dst port > 1023 && ack,
           // SMTP-3:
           allow src BASTION && dst INTERNAL_SMTP
              && tcp && src port > 1023 && dst port 25,
           // NNTP-2:
           allow src NNTP_FEED && dst INTERNAL_NNTP
              && tcp && src port 119 && dst port > 1023 && ack,
           // NNTP-3:
           allow src NNTP_FEED && dst INTERNAL_NNTP
              && tcp && src port > 1023 && dst port 119,
           // DNS-2:
           allow src BASTION && dst INTERNAL_DNS
              && udp && src port 53 && dst port 53,
           // DNS-4:
           allow src BASTION && dst INTERNAL_DNS
              && tcp && src port 53 && dst port > 1023 && ack,
           // DNS-5:
           allow src BASTION && dst INTERNAL_DNS
              && tcp && src port > 1023 && dst port 53,
           // Default-2:
           deny all);

=h program read-only
Returns a human-readable definition of the program the IPFilter element
is using to classify packets. At each step in the program, four bytes
of packet data are ANDed with a mask and compared against four bytes of
classifier pattern.

=a

IPClassifier, Classifier, CheckIPHeader, MarkIPHeader, CheckIPHeader2,
AddressInfo, tcpdump(1) */

class IPFilter : public Classifier { public:

  IPFilter();
  ~IPFilter();

  static void static_initialize();
  static void static_cleanup();

  const char *class_name() const		{ return "IPFilter"; }
  const char *port_count() const		{ return "1/-"; }
  const char *processing() const		{ return PUSH; }
  // this element does not need AlignmentInfo; override Classifier's "A" flag
  const char *flags() const			{ return ""; }

    int configure(Vector<String> &, ErrorHandler *);
    void add_handlers();

    void push(int port, Packet *);

    static String compressed_program_string(Element *, void *);

  enum {
    TYPE_NONE	= 0,		// data types
    TYPE_TYPE	= 1,
    TYPE_SYNTAX	= 2,
    TYPE_INT	= 3,

    TYPE_HOST	= 10,		// expression types
    TYPE_PROTO	= 11,
    TYPE_IPFRAG	= 12,
    TYPE_PORT	= 13,
    TYPE_TCPOPT = 14,

    TYPE_NET	= 30,		// shorthands
    TYPE_IPUNFRAG = 31,
    TYPE_IPECT	= 32,
    TYPE_IPCE	= 33,

    TYPE_FIELD	= 0x40000000,
    // bit 31 must be zero
    // bit 30 must be one
    // bits 29-21 represent IP protocol (9 bits); 0 means no protocol
    // bits 20-5 represent field offset into header in bits (16 bits)
    // bits 4-0 represent field length in bits minus one (5 bits)
    FIELD_PROTO_SHIFT = 21,
    FIELD_PROTO_MASK = (0x1FF << FIELD_PROTO_SHIFT),
    FIELD_OFFSET_SHIFT = 5,
    FIELD_OFFSET_MASK = (0xFFFF << FIELD_OFFSET_SHIFT),
    FIELD_LENGTH_SHIFT = 0,
    FIELD_LENGTH_MASK = (0x1F << FIELD_LENGTH_SHIFT),
    FIELD_CSUM	= (TYPE_FIELD | ((10*8) << FIELD_OFFSET_SHIFT) | 15),
    FIELD_IPLEN	= (TYPE_FIELD | ((2*8) << FIELD_OFFSET_SHIFT) | 15),
    FIELD_ID	= (TYPE_FIELD | ((4*8) << FIELD_OFFSET_SHIFT) | 15),
    FIELD_VERSION = (TYPE_FIELD | (0 << FIELD_OFFSET_SHIFT) | 3),
    FIELD_HL	= (TYPE_FIELD | (4 << FIELD_OFFSET_SHIFT) | 3),
    FIELD_TOS	= (TYPE_FIELD | ((1*8) << FIELD_OFFSET_SHIFT) | 7),
    FIELD_DSCP	= (TYPE_FIELD | ((1*8) << FIELD_OFFSET_SHIFT) | 5),
    FIELD_TTL	= (TYPE_FIELD | ((8*8) << FIELD_OFFSET_SHIFT) | 7),
    FIELD_TCP_WIN = (TYPE_FIELD | (IP_PROTO_TCP << FIELD_PROTO_SHIFT) | ((14*8) << FIELD_OFFSET_SHIFT) | 15),
    FIELD_ICMP_TYPE = (TYPE_FIELD | (IP_PROTO_ICMP << FIELD_PROTO_SHIFT) | (0 << FIELD_OFFSET_SHIFT) | 7)
  };

    enum {
	UNKNOWN = -1000
    };

    enum {
	SD_SRC = 1, SD_DST = 2, SD_AND = 3, SD_OR = 4
    };

    enum {
	OP_EQ = 0, OP_GT = 1, OP_LT = 2
    };

    enum {
	// if you change this, change click-fastclassifier.cc also
	TRANSP_FAKE_OFFSET = 64
    };

    enum {
	PERFORM_BINARY_SEARCH = 1,
	MIN_BINARY_SEARCH = 7
    };

  struct Primitive {

    int _type;
    int _data;

    int _op;
    bool _op_negated;

    int _srcdst;
    int _transp_proto;

    union {
      uint32_t u;
      int32_t i;
      unsigned char c[4];
    } _u, _mask;

    Primitive()				{ clear(); }

    void clear();
    void set_type(int, ErrorHandler *);
    void set_srcdst(int, ErrorHandler *);
    void set_transp_proto(int, ErrorHandler *);

    int set_mask(uint32_t full_mask, int shift, uint32_t provided_mask, ErrorHandler *);
    int check(const Primitive &, uint32_t provided_mask, ErrorHandler *);
    void add_exprs(Classifier *, Vector<int> &) const;

    bool has_transp_proto() const;
    bool negation_is_simple() const;
    void simple_negate();

    String unparse_type() const;
    String unparse_op() const;
    static String unparse_type(int srcdst, int type);
    static String unparse_transp_proto(int transp_proto);

   private:

    void add_comparison_exprs(Classifier *, Vector<int> &tree, int offset, int shift, bool swapped, bool op_negate) const;

  };

 private:

  Vector<uint32_t> _prog;

  int lookup(String word, int type, int transp_proto, uint32_t &data, ErrorHandler *errh) const;

  int parse_expr(const Vector<String> &, int, Vector<int> &, Primitive &,
		 ErrorHandler *);
  int parse_orexpr(const Vector<String> &, int, Vector<int> &, Primitive &,
		 ErrorHandler *);
  int parse_term(const Vector<String> &, int, Vector<int> &, Primitive &,
		 ErrorHandler *);
  int parse_factor(const Vector<String> &, int, Vector<int> &, Primitive &,
		 bool negated, ErrorHandler *);

  void length_checked_push(Packet *);

};


inline bool
IPFilter::Primitive::has_transp_proto() const
{
  return _transp_proto >= 0;
}

inline bool
IPFilter::Primitive::negation_is_simple() const
{
  if (_type == TYPE_PROTO)
    return true;
  else if (_transp_proto >= 0)
    return false;
  else
    return _type == TYPE_HOST || (_type & TYPE_FIELD) || _type == TYPE_IPFRAG;
}

CLICK_ENDDECLS
#endif
