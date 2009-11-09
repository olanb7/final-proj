#ifndef CLICK_SPANTREE_HH
#define CLICK_SPANTREE_HH
#include <click/element.hh>
#include "bridgemessage.hh"
#include <click/timer.hh>
CLICK_DECLS
class Suppressor;
class EtherSwitch;

class EtherSpanTree : public Element {

public:
  EtherSpanTree();
  ~EtherSpanTree();

  const char *class_name() const		{ return "EtherSpanTree"; }
  const char *port_count() const		{ return "-/="; }
  const char *processing() const		{ return "h/h"; }

  int configure(Vector<String> &, ErrorHandler *);
  int initialize(ErrorHandler *);

  static String read_msgs(Element* f, void *);
  void add_handlers();


  void periodic();

  bool expire();
  void find_best();
  void find_tree();		// Returns true iff there is a change

  void push(int port, Packet* p);
  Packet* generate_packet(int output);

private:
  Suppressor* _input_sup;
  Suppressor* _output_sup;
  EtherSwitch* _switch;
  Timestamp* _topology_change;	// If set, tc should be sent with messages.
  bool _send_tc_msg;		// If true, tcm should be sent to root port.

  uint64_t _bridge_id;		// Should be 48 bits

  uint16_t _bridge_priority;	// High == unlikely to become the root node
  uint16_t _long_cache_timeout; // in seconds

  uint8_t _addr[6];

  BridgeMessage _best;


  // Do not change the order of the PortState enum tags.  (see set_state())
  enum PortState {BLOCK, LISTEN, LEARN, FORWARD};
  struct PortInfo {
    PortState state;
    Timestamp since;		// When the port entered the state
    bool needs_tca;
    BridgeMessage msg;
    PortInfo() { state = BLOCK; needs_tca = false; }
  };

  bool set_state(int i, PortState state); // Only expects BLOCK or FORWARD

  Vector<PortInfo> _port;

  Timer _hello_timer;
  static void hello_hook(Timer *, void *);

};

CLICK_ENDDECLS
#endif
