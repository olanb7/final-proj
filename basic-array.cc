#include <click/config.h>
#include "basic.hh"
#include <click/element.hh>
#include <click/timer.hh>
#include <clicknet/ether.h>
#include <click/etheraddress.hh>
#include <clicknet/wifi.h>
#include <click/etheraddress.hh>
#include <click/confparse.hh>
#include <click/vector.hh>
#include <elements/wifi/availablerates.hh>
#include <elements/wifi/wirelessinfo.hh>
#include <click/list.hh>
#include <click/error.hh>
#include <string>
#if CLICK_USERLEVEL
# include <sys/time.h>
# include <sys/resource.h>
# include <unistd.h>
#endif

#define show_debug 1		// set true to output debug messages from getEMA funcion
#define window 5 		// define window size in seconds

CLICK_DECLS

Basic::Basic()
  : _timer(this),
    _logfile(0)
{
}

Basic::~Basic()
{
}

int
Basic::initialize (ErrorHandler *) {

	_timer.initialize(this);
	_timer.schedule_after_sec(1);
	return 0;
}

void Basic::print_stations(StationList &l) {
	size_t n = 0;
	StringAccum sa, head;

	Timestamp now = Timestamp::now();
	//system("clear");

	head << "\nNo.\t MAC\t\t\t RSSI\t Avg\t\t Last Beacon (s)\n";
	head <<   "---\t ---\t\t\t ----\t ---\t\t ---------------\n";
	click_chatter("%s", head.c_str());

	for (StationList::const_iterator it = l.begin(); it != l.end(); ++it, ++n) {
		Timestamp diff = now;
		sa << "\n#" << n;
		sa << "\t " << it->mac->unparse().c_str();
		sa << "\t " << it->rssi;
		for(int j = 0; j < k.size(); j++)
			sa << "\t " << it->ema.at(j);
		diff -= *it->time;
		if (diff < 1) { 
			sa << "\t \e[32m" << diff << "\e[0m"; }
		else { 	
			sa << "\t \e[31m" << diff << "\e[0m"; }
		
	}
	click_chatter("%s", sa.c_str());
}

Basic::station *
Basic::lookup(station &chksta, StationList &l) {
	size_t n = 0;
	for (StationList::iterator lkup = l.begin(); lkup != l.end(); ++lkup, ++n) {

		// if MAC address is found in list, return pointer to it
		if(!strcmp(chksta.mac->unparse().c_str(), lkup->mac->unparse().c_str())) {
				return lkup.get();
		}
	}
	return (struct station*)NULL;
}

void Basic::run_timer(Timer *) {
	getEMA(_sta_list);
	print_stations(_sta_list);
	_timer.schedule_after_sec(1);
}

void Basic::getEMA(StationList &l) {

	k.push_back(0.3333333);
	k.push_back(0.1818181);
	
	StringAccum debug;

	debug << "\n\e[104m------DEBUG------\e[0m";
	// calculate ema for each station in StationList
	for (StationList::iterator sta = l.begin(); sta != l.end(); ++sta) {
		debug << "\n\tMAC: " << sta->mac->unparse().c_str() << "\n\ttotal = ";
		sta->ave = 0;

		// iterate through packets got in last sec and sum	
		for(int i = 0; i < sta->past_packets.size(); i++) {
			sta->ave += sta->past_packets.at(i);
			debug << sta->past_packets.at(i) << " + ";
		}
			debug << " = " << sta->ave << "\n\tpacket size = " << sta->past_packets.size();

		// get mean average from the packets captured in last sec
		if (sta->past_packets.empty()) {
			sta->ave = 0;
		}
		else {
			sta->ave = sta->ave / sta->past_packets.size();
			debug << "\n\ttotal / packet size = " << sta->ave;
		}	

		// calculate the ema
		for(int j = 0; j < k.size(); j++) {
			if (sta->first_run) {
				sta->ema.push_back(sta->ave);
				if (j == k.at(-1))
					sta->first_run = 0;
			}
			else {
				//debug << "\n\n\tEMA: " << k.at(j) << " x (" << sta->ave << " - " << sta->ema.at(j) << ") + " << sta->ema.at(j);
				//double ema = ( k.at(j) * ( sta->ave - sta->ema.at(j) ) ) + sta->ema.at(j);
				//sta->ema.push_back(ema); 	
				debug << " = \t" << ema << "\n";
			}
		}

		// empty the array of packets caught in last sec
		sta->past_packets.erase(sta->past_packets.begin(), sta->past_packets.end());

		sta->flag = 1;

	}
	debug << "\e[104m----DEBUG-END----\e[0m\n";
	if (show_debug == 1)
			click_chatter("%s", debug.take_string().c_str());

}

void Basic::keepTrack(station &sta){

	// if arrays are size of window, remove element
	if (sta.past_packets.size() >= window) {
			sta.past_packets.pop_front();
	}
	// put new rssi in array
	sta.past_packets.push_back(sta.rssi);	
}

void
Basic::push(int, Packet *p) {

	StringAccum log, fn;

	struct click_wifi *w = (struct click_wifi *) p->data();
	struct click_wifi_extra *ceh = WIFI_EXTRA_ANNO(p);
	
	struct station *sta = new station;

	sta->mac = new EtherAddress(w->i_addr3);
	sta->rssi = ceh->rssi;

	if (!_sta_list.empty()) {

      		// list not empty, so lookup
		struct station *sta_dupe = lookup(*sta, _sta_list);
		
		if (sta_dupe) {
			// already in list, so update
			sta_dupe->time->set_now();
			sta_dupe->rssi = sta->rssi;
			keepTrack(*sta_dupe);

			log << *sta_dupe->time << "\t";
			log << sta_dupe->rssi << "\t";

			if (sta_dupe->flag == 1) {
				for(int j = 0; j < k.size(); j++) {
					log << sta_dupe->ema.at(j) << "\t";
					sta_dupe->flag = 0;
				}
			}
		}			
		else {
			// not in list, so add
			sta->time = new Timestamp(Timestamp::now());
			sta->first_run = 1;
			keepTrack(*sta);

			log << *sta->time << "\t";
			log << sta->rssi << "\t";

			_sta_list.push_back(sta);
		}
	}
	else {
		// list empty, so add
		sta->time = new Timestamp(Timestamp::now());
		sta->first_run = 1;
		keepTrack(*sta);

		log << *sta->time << "\t";
		log << sta->rssi << "\t";

		_sta_list.push_back(sta);
	}

	
	log << "\n";
	
	// log packets to file*/
	#if CLICK_USERLEVEL
	fn << "/home/olan/logs/" << sta->mac->unparse().c_str() << ".txt";
	_filename = fn.take_string();

	if (_filename) {
		_logfile = fopen(_filename.c_str(), "a");
		if (!_logfile)
			click_chatter("ERROR: %s, can't open logfile for appending\n", _filename.c_str());

		fwrite(log.data(), 1, log.length(), _logfile);
	}
	else {
		click_chatter("Wrong filename : %s\n", _filename.c_str());	
	}

  	if (_logfile)
  		fclose(_logfile);
	_logfile = 0;
	#endif

	output(0).push(p);
}

EXPORT_ELEMENT(Basic)
CLICK_ENDDECLS


