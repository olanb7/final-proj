#ifndef CLICK_STATIONSTATS_HH
#define CLICK_STATIONSTATS_HH
#include <click/element.hh>
#include <click/etheraddress.hh>
#include <click/hashcontainer.hh>
#include <click/hashallocator.hh>
#include <click/sync.hh>
#include <click/timer.hh>
#include <click/list.hh>
CLICK_DECLS

class StationStats : public Element
{

public:

  StationStats();
  ~StationStats();

  const char *class_name() const	{ return "StationStats"; }
  const char *port_count() const	{ return PORTS_1_1; }
  const char *processing() const	{ return PUSH; }
  
  void push(int port, Packet *p);

  struct station{
  	  typedef EtherAddress _mac;
	  Timestamp _last_seen;
	  List_member<station> _link;
  };

private:

  typedef List<station, &station::_link> Link;
  Link _list_link;
};
CLICK_ENDDECLS
#endif


