#ifndef CLICK_TCPREWRITER_HH
#define CLICK_TCPREWRITER_HH
#include "elements/ip/iprw.hh"
#include <clicknet/tcp.h>
CLICK_DECLS

/*
=c

TCPRewriter(INPUTSPEC1, ..., INPUTSPECn [, KEYWORDS])

=s nat

rewrites TCP packets' addresses, ports, and sequence numbers

=d

Rewrites TCP flows by changing their source address, source port, destination
address, and/or destination port, and optionally, their sequence numbers and
acknowledgement numbers. It also changes the destination IP address
annotation; see the DST_ANNO keyword argument below.

This element is an IPRewriter-like element. Please read the IPRewriter
documentation for more information and a detailed description of its
INPUTSPEC arguments.

In addition to IPRewriter's functionality, the TCPRewriter element can add or
subtract amounts from incoming packets' sequence and acknowledgement numbers,
including any SACK acknowledgement numbers. Each newly created mapping starts
with these deltas at zero; other elements can request changes to a given
mapping. For example, FTPPortMapper uses this facility.

Keyword arguments determine how often stale mappings should be removed.

=over 5

=item TCP_TIMEOUT I<time>

Time out TCP connections every I<time> seconds. Default is 24 hours.

=item TCP_DONE_TIMEOUT I<time>

Time out completed TCP connections every I<time> seconds. Default is 30
seconds. FIN and RST flags mark TCP connections as complete.

=item REAP_TCP I<time>

Reap timed-out TCP connections every I<time> seconds. If no packets
corresponding to a given mapping have been seen for TCP_TIMEOUT, remove the
mapping as stale. Default is 1 hour.

=item REAP_TCP_DONE I<time>

Reap timed-out completed TCP connections every I<time> seconds. Default is 10
seconds.

=item DST_ANNO

Boolean. If true, then set the destination IP address annotation on passing
packets to the rewritten destination address. Default is true.

=back

=h mappings read-only

Returns a human-readable description of the TCPRewriter's current set of
mappings.

=a IPRewriter, IPAddrRewriter, IPAddrPairRewriter, IPRewriterPatterns,
FTPPortMapper */

class TCPRewriter : public IPRw { public:

  class TCPMapping : public Mapping { public:

    TCPMapping(bool dst_anno);

    TCPMapping *reverse() const		{ return static_cast<TCPMapping *>(_reverse); }

    bool have_seqno_delta() const	{ return _delta || _old_delta; }

    int update_seqno_delta(tcp_seq_t old_seqno, int32_t delta);
    tcp_seq_t new_seq(tcp_seq_t) const;
    tcp_seq_t new_ack(tcp_seq_t) const;

    void apply(WritablePacket *p);

    String s() const;

   private:

    tcp_seq_t _trigger;
    int32_t _delta;
    int32_t _old_delta;

    uint32_t apply_sack(click_tcp *, int transport_length);

  };

  TCPRewriter();
  ~TCPRewriter();

  const char *class_name() const		{ return "TCPRewriter"; }
  void *cast(const char *);
  const char *port_count() const		{ return "1-/1-256"; }
  const char *processing() const		{ return PUSH; }

  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);
  void cleanup(CleanupStage);
  void take_state(Element *, ErrorHandler *);

  int notify_pattern(Pattern *, ErrorHandler *);
  TCPMapping *apply_pattern(Pattern *, int ip_p, const IPFlowID &, int, int);
  TCPMapping *get_mapping(int ip_p, const IPFlowID &) const;

  void push(int, Packet *);

  void add_handlers();
  int llrpc(unsigned, void *);

 private:

  Map _tcp_map;
  Mapping *_tcp_done;
  Mapping *_tcp_done_tail;

  Vector<InputSpec> _input_specs;
  bool _dst_anno;

  int _tcp_gc_interval;
  int _tcp_done_gc_interval;
  Timer _tcp_gc_timer;
  Timer _tcp_done_gc_timer;
  int _tcp_timeout_jiffies;
  int _tcp_done_timeout_jiffies;

  int _nmapping_failures;

  static void tcp_gc_hook(Timer *, void *);
  static void tcp_done_gc_hook(Timer *, void *);

  static String dump_mappings_handler(Element *, void *);
  static String dump_nmappings_handler(Element *, void *);
  static String dump_patterns_handler(Element *, void *);

};

inline TCPRewriter::TCPMapping *
TCPRewriter::get_mapping(int ip_p, const IPFlowID &in) const
{
  if (ip_p == IP_PROTO_TCP)
    return static_cast<TCPMapping *>(_tcp_map[in]);
  else
    return 0;
}

inline tcp_seq_t
TCPRewriter::TCPMapping::new_seq(tcp_seq_t seqno) const
{
  return seqno + (SEQ_GEQ(seqno, _trigger) ? _delta : _old_delta);
}

inline tcp_seq_t
TCPRewriter::TCPMapping::new_ack(tcp_seq_t ackno) const
{
  tcp_seq_t mod_ackno = ackno - _delta;
  return (SEQ_GEQ(mod_ackno, _trigger) ? mod_ackno : ackno - _old_delta);
}

CLICK_ENDDECLS
#endif
