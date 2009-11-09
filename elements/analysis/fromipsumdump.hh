// -*- mode: c++; c-basic-offset: 4 -*-
#ifndef CLICK_FROMIPSUMDUMP_HH
#define CLICK_FROMIPSUMDUMP_HH
#include <click/element.hh>
#include <click/task.hh>
#include <click/timer.hh>
#include <click/notifier.hh>
#include <click/ipflowid.hh>
#include "elements/userlevel/fromfile.hh"
#include "ipsumdumpinfo.hh"
CLICK_DECLS

/*
=c

FromIPSummaryDump(FILENAME [, I<keywords> STOP, TIMING, ACTIVE, ZERO, CHECKSUM, PROTO, MULTIPACKET, SAMPLE, CONTENTS, FLOWID])

=s traces

reads packets from an IP summary dump file

=d

Reads IP packet descriptors from a file produced by ToIPSummaryDump, then
creates packets containing info from the descriptors and pushes them out the
output. Optionally stops the driver when there are no more packets.

The file may be compressed with gzip(1) or bzip2(1); FromIPSummaryDump will
run zcat(1) or bzcat(1) to uncompress it.

FromIPSummaryDump reads from the file named FILENAME unless FILENAME is a
single dash 'C<->', in which case it reads from the standard input. It will
not uncompress the standard input, however.

Keyword arguments are:

=over 8

=item STOP

Boolean. If true, then FromIPSummaryDump will ask the router to stop when it
is done reading. Default is false.

=item TIMING

Boolean. If true, then FromIPSummaryDump tries to maintain the timing of the
original packet stream. The first packet is emitted immediately; thereafter,
FromIPSummaryDump maintains the delays between packets. Default is false.

=item ACTIVE

Boolean. If false, then FromIPSummaryDump will not emit packets (until the
'C<active>' handler is written). Default is true.

=item ZERO

Boolean. Determines the contents of packet data not set by the dump. If true
E<lparen>the default), this data is zero. If false, it is random garbage.

=item CHECKSUM

Boolean. If true, then output packets' IP, TCP, and UDP checksums are set, and
have actual data bytes covering the entire IP length (whether or not those
data bytes were defined). If false (the default), then the checksum fields
contain random garbage, and output packets may be shorter than their IP
headers' length fields (the EXTRA_LENGTH annotation is set to account for the
difference).

=item PROTO

Byte (0-255). Sets the IP protocol used for output packets when the dump
doesn't specify a protocol. Default is 6 (TCP).

=item MULTIPACKET

Boolean. If true, then FromIPSummaryDump will emit multiple packets for each
line---specifically, it will emit as many packets as the packet count field
specifies. Default is false.

=item SAMPLE

Unsigned real number between 0 and 1. FromIPSummaryDump will output each
packet with probability SAMPLE. Default is 1. FromIPSummaryDump uses
fixed-point arithmetic, so the actual sampling probability may differ
substantially from the requested sampling probability. Use the
C<sampling_prob> handler to find out the actual probability. If MULTIPACKET is
true, then the sampling probability applies separately to the multiple packets
generated per record.

=item CONTENTS

String, containing a space-separated list of content names (see
ToIPSummaryDump for the possibilities). Defines the default contents of the
dump.

=item FLOWID

String, containing a space-separated flow ID (source address, source port,
destination address, destination port, and, optionally, protocol). Defines the
IP addresses and ports used by default. Any flow information in the input file
will override this setting.

=back

Only available in user-level processes.

=n

Packets generated by FromIPSummaryDump always have IP version 4 and a correct
IP header length. The default IP protocol is TCP (6) and the default
time-to-live is 100. The rest of the packet data is zero or garbage, unless
set by the dump. Generated packets will usually have short lengths, but the
extra header length annotations are set correctly.

FromIPSummaryDump is a notifier signal, active when the element is active and
the dump contains more packets.

=h sampling_prob read-only

Returns the sampling probability (see the SAMPLE keyword argument).

=h active read/write

Value is a Boolean.

=h encap read-only

Returns 'IP'. Useful for ToDump's USE_ENCAP_FROM option.

=h filesize read-only

Returns the length of the FromIPSummaryDump file, in bytes, or "-" if that
length cannot be determined.

=h filepos read-only

Returns FromIPSummaryDump's position in the file, in bytes.

=h stop write-only

When written, sets 'active' to false and stops the driver.

=a

ToIPSummaryDump */

class FromIPSummaryDump : public Element, public IPSummaryDumpInfo { public:

    FromIPSummaryDump();
    ~FromIPSummaryDump();

    const char *class_name() const	{ return "FromIPSummaryDump"; }
    const char *port_count() const	{ return PORTS_0_1; }
    const char *processing() const	{ return AGNOSTIC; }
    void *cast(const char *);

    int configure(Vector<String> &, ErrorHandler *);
    int initialize(ErrorHandler *);
    void cleanup(CleanupStage);
    void add_handlers();

    bool run_task(Task *);
    Packet *pull(int);
    void run_timer(Timer *timer);

  private:

    enum { SAMPLING_SHIFT = 28 };

    FromFile _ff;

    Vector<const IPSummaryDump::FieldReader *> _fields;
    Vector<int> _field_order;
    uint16_t _default_proto;
    uint32_t _sampling_prob;
    IPFlowID _flowid;
    uint32_t _aggregate;

    bool _stop : 1;
    bool _format_complaint : 1;
    bool _zero : 1;
    bool _checksum : 1;
    bool _active : 1;
    bool _multipacket : 1;
    bool _have_flowid : 1;
    bool _have_aggregate : 1;
    bool _binary : 1;
    bool _timing : 1;
    bool _have_timing : 1;
    Packet *_work_packet;
    uint32_t _multipacket_length;
    Timestamp _multipacket_timestamp_delta;
    Timestamp _multipacket_end_timestamp;
    Timestamp _timing_offset;

    Task _task;
    ActiveNotifier _notifier;
    Timer _timer;

    int _minor_version;
    IPFlowID _given_flowid;

    int read_binary(String &, ErrorHandler *);

    static int sort_fields_compare(const void *, const void *, void *);
    void bang_data(const String &, ErrorHandler *);
    void bang_proto(const String &line, const char *type, ErrorHandler *errh);
    void bang_flowid(const String &, ErrorHandler *);
    void bang_aggregate(const String &, ErrorHandler *);
    void bang_binary(const String &, ErrorHandler *);
    void check_defaults();
    bool check_timing(Packet *p);
    Packet *read_packet(ErrorHandler *);
    Packet *handle_multipacket(Packet *);

    static String read_handler(Element *, void *);
    static int write_handler(const String &, Element *, void *, ErrorHandler *);

};

CLICK_ENDDECLS
#endif
