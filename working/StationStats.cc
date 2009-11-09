#include <click/config.h>
#include "StationStats.hh"
CLICK_DECLS

StationStats::StationStats()
{
}

StationStats::~StationStats()
{
}

Packet *
StationStats::push(port, Packet *p)
{
  click_ether *e = (click_ether *)p_in->data();
  if (p_in->length() >= sizeof(click_ether) + NBYTES &&
      ntohs(e->ether_type) == _et) {
    log_entry d;
    d.timestamp = p_in->timestamp_anno();
    click_chatter("TIMESTAMP: %s" d.timestamp);
    }
    return p;
}


CLICK_ENDDECLS
EXPORT_ELEMENT(StationStats)
