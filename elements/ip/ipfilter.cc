/*
 * ipfilter.{cc,hh} -- IP-packet filter with tcpdumplike syntax
 * Eddie Kohler
 *
 * Copyright (c) 2000-2007 Mazu Networks, Inc.
 * Copyright (c) 2004-2007 Regents of the University of California
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, subject to the conditions
 * listed in the Click LICENSE file. These conditions include: you must
 * preserve this copyright notice, and you cannot mention the copyright
 * holders in advertising related to the Software without their permission.
 * The Software is provided WITHOUT ANY WARRANTY, EXPRESS OR IMPLIED. This
 * notice is a summary of the Click LICENSE file; the license in that file is
 * legally binding.
 */

#include <click/config.h>
#include "ipfilter.hh"
#include <click/glue.hh>
#include <click/error.hh>
#include <click/confparse.hh>
#include <click/straccum.hh>
#include <clicknet/ip.h>
#include <clicknet/tcp.h>
#include <clicknet/icmp.h>
#include <click/hashmap.hh>
#include <click/integers.hh>
#include <click/nameinfo.hh>
CLICK_DECLS

static const StaticNameDB::Entry type_entries[] = {
    { "ce", IPFilter::TYPE_IPCE },
    { "dest", IPFilter::TYPE_SYNTAX },
    { "dscp", IPFilter::FIELD_DSCP },
    { "dst", IPFilter::TYPE_SYNTAX },
    { "ect", IPFilter::TYPE_IPECT },
    { "frag", IPFilter::TYPE_IPFRAG },
    { "hl", IPFilter::FIELD_HL },
    { "host", IPFilter::TYPE_HOST },
    { "id", IPFilter::FIELD_ID },
    { "ip", IPFilter::TYPE_SYNTAX },
    { "len", IPFilter::FIELD_IPLEN },
    { "net", IPFilter::TYPE_NET },
    { "not", IPFilter::TYPE_SYNTAX },
    { "opt", IPFilter::TYPE_TCPOPT },
    { "port", IPFilter::TYPE_PORT },
    { "proto", IPFilter::TYPE_PROTO },
    { "src", IPFilter::TYPE_SYNTAX },
    { "tos", IPFilter::FIELD_TOS },
    { "ttl", IPFilter::FIELD_TTL },
    { "type", IPFilter::FIELD_ICMP_TYPE },
    { "unfrag", IPFilter::TYPE_IPUNFRAG },
    { "vers", IPFilter::FIELD_VERSION },
    { "win", IPFilter::FIELD_TCP_WIN }
};

static const StaticNameDB::Entry tcp_opt_entries[] = {
    { "ack", TH_ACK },
    { "fin", TH_FIN },
    { "psh", TH_PUSH },
    { "rst", TH_RST },
    { "syn", TH_SYN },
    { "urg", TH_URG }
};

static const uint32_t db2type[] = {
    IPFilter::TYPE_PROTO, IPFilter::TYPE_PORT, IPFilter::TYPE_PORT,
    IPFilter::TYPE_TCPOPT, IPFilter::FIELD_ICMP_TYPE
};

static String
unparse_word(int type, int proto, const String &word)
{
    String tn = IPFilter::Primitive::unparse_type(0, type);
    String tr = IPFilter::Primitive::unparse_transp_proto(proto);
    if (tn)
	tn += " ";
    if (tr || (word && tn))
	tr += " ";
    return tn + tr + word;
}

int
IPFilter::lookup(String word, int type, int proto, uint32_t &data, ErrorHandler *errh) const
{
    // type queries always win if they occur
    if (type == 0 || type == TYPE_TYPE)
	if (NameInfo::query(NameInfo::T_IPFILTER_TYPE, this, word, &data, sizeof(uint32_t)))
	    return (data == TYPE_SYNTAX ? -1 : TYPE_TYPE);

    // query each relevant database
    int got[5];
    int32_t val[5];
    got[0] = NameInfo::query(NameInfo::T_IP_PROTO, this, word, &val[0], sizeof(uint32_t));
    got[1] = NameInfo::query(NameInfo::T_TCP_PORT, this, word, &val[1], sizeof(uint32_t));
    got[2] = NameInfo::query(NameInfo::T_UDP_PORT, this, word, &val[2], sizeof(uint32_t));
    got[3] = NameInfo::query(NameInfo::T_TCP_OPT, this, word, &val[3], sizeof(uint32_t));
    got[4] = NameInfo::query(NameInfo::T_ICMP_TYPE, this, word, &val[4], sizeof(uint32_t));

    // exit if no match
    if (!got[0] && !got[1] && !got[2] && !got[3] && !got[4])
	return -1;

    // filter
    int tgot[5];
    tgot[0] = got[0] && (type == 0 || type == TYPE_PROTO);
    tgot[1] = got[1] && (type == 0 || type == TYPE_PORT)
	&& (proto == UNKNOWN || proto == IP_PROTO_TCP || proto == IP_PROTO_TCP_OR_UDP);
    tgot[2] = got[2] && (type == 0 || type == TYPE_PORT)
	&& (proto == UNKNOWN || proto == IP_PROTO_UDP || proto == IP_PROTO_TCP_OR_UDP);
    tgot[3] = got[3] && (type == 0 || type == TYPE_TCPOPT)
	&& (proto == UNKNOWN || proto == IP_PROTO_TCP || proto == IP_PROTO_TCP_OR_UDP);
    tgot[4] = got[4] && (type == 0 || type == FIELD_ICMP_TYPE)
	&& (proto == UNKNOWN || proto == IP_PROTO_ICMP);

    // remove one of TCP and UDP port if they give the same value
    if (tgot[1] && tgot[2] && val[1] == val[2])
	tgot[2] = false;

    // return
    int ngot = tgot[0] + tgot[1] + tgot[2] + tgot[3] + tgot[4];
    if (ngot == 1) {
	for (int i = 0; i < 5; i++)
	    if (tgot[i]) {
		data = val[i];
		return db2type[i];
	    }
    }
    StringAccum sa;
    for (int i = 0; i < 5; i++)
	if (got[i]) {
	    if (sa)
		sa << ", ";
	    sa << '\'' << unparse_word(db2type[i], proto, word) << '\'';
	}
    if (errh)
	errh->error("'%s' is %s; try %s", unparse_word(type, proto, word).c_str(), (ngot > 1 ? "ambiguous" : "meaningless"), sa.c_str());
    return -2;
}

static NameDB *dbs[2];

void
IPFilter::static_initialize()
{
    dbs[0] = new StaticNameDB(NameInfo::T_IPFILTER_TYPE, String(), type_entries, sizeof(type_entries) / sizeof(type_entries[0]));
    dbs[1] = new StaticNameDB(NameInfo::T_TCP_OPT, String(), tcp_opt_entries, sizeof(tcp_opt_entries) / sizeof(tcp_opt_entries[0]));
    NameInfo::installdb(dbs[0], 0);
    NameInfo::installdb(dbs[1], 0);
}

void
IPFilter::static_cleanup()
{
    delete dbs[0];
    delete dbs[1];
}


IPFilter::IPFilter()
{
}

IPFilter::~IPFilter()
{
}

//
// CONFIGURATION
//

void
IPFilter::Primitive::clear()
{
  _type = _srcdst = 0;
  _transp_proto = UNKNOWN;
  _data = 0;
  _op = OP_EQ;
  _op_negated = false;
}

void
IPFilter::Primitive::set_type(int x, ErrorHandler *errh)
{
  if (_type)
    errh->error("type specified twice");
  _type = x;
}

void
IPFilter::Primitive::set_srcdst(int x, ErrorHandler *errh)
{
  if (_srcdst)
    errh->error("'src' or 'dst' specified twice");
  _srcdst = x;
}

void
IPFilter::Primitive::set_transp_proto(int x, ErrorHandler *errh)
{
  if (_transp_proto != UNKNOWN && _transp_proto != x)
    errh->error("transport protocol specified twice");
  _transp_proto = x;
}

int
IPFilter::Primitive::set_mask(uint32_t full_mask, int shift, uint32_t provided_mask, ErrorHandler *errh)
{
    uint32_t data = _u.u;
    uint32_t this_mask = (provided_mask ? provided_mask : full_mask);
    if ((this_mask & full_mask) != this_mask)
	return errh->error("mask 0x%X out of range (0-0x%X)", provided_mask, full_mask);

    if (_op == OP_GT || _op == OP_LT) {
	// Check for comparisons that are always true or false.
	if ((_op == OP_LT && (data == 0 || data > this_mask))
	    || (_op == OP_GT && data >= this_mask)) {
	    bool will_be = (_op == OP_LT && data > this_mask ? !_op_negated : _op_negated);
	    errh->warning("relation '%s %u' is always %s (range 0-%u)", unparse_op().c_str(), data, (will_be ? "true" : "false"), this_mask);
	    _u.u = _mask.u = 0;
	    _op_negated = !will_be;
	    _op = OP_EQ;
	    return 0;
	}

	// value < X == !(value > (X - 1))
	if (_op == OP_LT) {
	    _u.u--;
	    _op_negated = !_op_negated;
	    _op = OP_GT;
	}

	_u.u = (_u.u << shift) | ((1 << shift) - 1);
	_mask.u = (this_mask << shift) | ((1 << shift) - 1);
	// Want (_u.u & _mask.u) == _u.u.
	// So change 'tcp[0] & 5 > 2' into the equivalent 'tcp[0] & 5 > 1':
	// find the highest bit in _u that is not set in _mask,
	// and turn on all lower bits.
	if ((_u.u & _mask.u) != _u.u) {
	    uint32_t full_mask_u = (full_mask << shift) | ((1 << shift) - 1);
	    uint32_t missing_bits = (_u.u & _mask.u) ^ (_u.u & full_mask_u);
	    uint32_t add_mask = 0xFFFFFFFFU >> ffs_msb(missing_bits);
	    _u.u = (_u.u | add_mask) & _mask.u;
	}
	return 0;
    }

    if (data > full_mask)
	return errh->error("value %u out of range (0-%u)", data, full_mask);

    _u.u = data << shift;
    _mask.u = this_mask << shift;
    return 0;
}

String
IPFilter::Primitive::unparse_type(int srcdst, int type)
{
  StringAccum sa;

  switch (srcdst) {
   case SD_SRC: sa << "src "; break;
   case SD_DST: sa << "dst "; break;
   case SD_OR: sa << "src or dst "; break;
   case SD_AND: sa << "src and dst "; break;
  }

  switch (type) {
   case TYPE_NONE: sa << "<none>"; break;
   case TYPE_HOST: sa << "ip host"; break;
   case TYPE_PROTO: sa << "proto"; break;
   case TYPE_IPFRAG: sa << "ip frag"; break;
   case TYPE_PORT: sa << "port"; break;
   case TYPE_TCPOPT: sa << "tcp opt"; break;
   case TYPE_NET: sa << "ip net"; break;
   case TYPE_IPUNFRAG: sa << "ip unfrag"; break;
   case TYPE_IPECT: sa << "ip ect"; break;
   case TYPE_IPCE: sa << "ip ce"; break;
   default:
    if (type & TYPE_FIELD) {
      switch (type) {
       case FIELD_IPLEN: sa << "ip len"; break;
       case FIELD_ID: sa << "ip id"; break;
       case FIELD_VERSION: sa << "ip vers"; break;
       case FIELD_HL: sa << "ip hl"; break;
       case FIELD_TOS: sa << "ip tos"; break;
       case FIELD_DSCP: sa << "ip dscp"; break;
       case FIELD_TTL: sa << "ip ttl"; break;
       case FIELD_TCP_WIN: sa << "tcp win"; break;
       case FIELD_ICMP_TYPE: sa << "icmp type"; break;
       default:
	if (type & FIELD_PROTO_MASK)
	  sa << unparse_transp_proto((type & FIELD_PROTO_MASK) >> FIELD_PROTO_SHIFT);
	else
	  sa << "ip";
	sa << "[...]";
	break;
      }
    } else
      sa << "<unknown type " << type << ">";
    break;
  }

  return sa.take_string();
}

String
IPFilter::Primitive::unparse_transp_proto(int transp_proto)
{
  switch (transp_proto) {
   case UNKNOWN: return "";
   case IP_PROTO_ICMP: return "icmp";
   case IP_PROTO_IGMP: return "igmp";
   case IP_PROTO_IPIP: return "ipip";
   case IP_PROTO_TCP: return "tcp";
   case IP_PROTO_UDP: return "udp";
   case IP_PROTO_TCP_OR_UDP: return "tcpudp";
   case IP_PROTO_TRANSP: return "transp";
   default: return "ip proto " + String(transp_proto);
  }
}

String
IPFilter::Primitive::unparse_type() const
{
  return unparse_type(_srcdst, _type);
}

String
IPFilter::Primitive::unparse_op() const
{
  if (_op == OP_GT)
    return (_op_negated ? "<=" : ">");
  else if (_op == OP_LT)
    return (_op_negated ? ">=" : "<");
  else
    return (_op_negated ? "!=" : "=");
}

void
IPFilter::Primitive::simple_negate()
{
  assert(negation_is_simple());
  _op_negated = !_op_negated;
  if (_type == TYPE_PROTO && _mask.u == 0xFF)
    _transp_proto = (_op_negated ? UNKNOWN : _u.i);
}

int
IPFilter::Primitive::check(const Primitive &p, uint32_t provided_mask, ErrorHandler *errh)
{
  int old_srcdst = _srcdst;

  // if _type is erroneous, return -1 right away
  if (_type < 0)
    return -1;

  // set _type if it was not specified
  if (!_type) {

   retry:
    switch (_data) {

     case TYPE_HOST:
     case TYPE_NET:
     case TYPE_TCPOPT:
      _type = _data;
      if (!_srcdst)
	_srcdst = p._srcdst;
      break;

     case TYPE_PROTO:
      _type = TYPE_PROTO;
      break;

     case TYPE_PORT:
      _type = TYPE_PORT;
      if (!_srcdst)
	_srcdst = p._srcdst;
      if (_transp_proto == UNKNOWN)
	_transp_proto = p._transp_proto;
      break;

     case TYPE_INT:
      if (!(p._type & TYPE_FIELD) && p._type != TYPE_PROTO && p._type != TYPE_PORT)
	return errh->error("specify header field or 'port'");
      _data = p._type;
      goto retry;

     case TYPE_NONE:
      if (_transp_proto != UNKNOWN)
	_type = TYPE_PROTO;
      else
	return errh->error("partial directive");
      break;

     default:
      if (_data & TYPE_FIELD) {
	_type = _data;
	if ((_type & FIELD_PROTO_MASK) && _transp_proto == UNKNOWN)
	  _transp_proto = (_type & FIELD_PROTO_MASK) >> FIELD_PROTO_SHIFT;
      } else
	return errh->error("unknown type '%s'", unparse_type(0, _data).c_str());
      break;

    }
  }

  // check that _data and _type agree
  switch (_type) {

   case TYPE_HOST:
    if (_data != TYPE_HOST)
      return errh->error("IP address missing in 'host' directive");
    if (_op != OP_EQ)
      return errh->error("can't use relational operators with 'host'");
    _mask.u = (provided_mask ? provided_mask : 0xFFFFFFFFU);
    break;

   case TYPE_NET:
    if (_data != TYPE_NET)
      return errh->error("IP prefix missing in 'net' directive");
    if (_op != OP_EQ)
      return errh->error("can't use relational operators with 'net'");
    _type = TYPE_HOST;
    // _mask already set
    if (provided_mask)
	_mask.u = provided_mask;
    break;

   case TYPE_PROTO:
    if (_data == TYPE_INT || _data == TYPE_PROTO) {
      if (_transp_proto != UNKNOWN && _transp_proto != _u.i)
	return errh->error("transport protocol specified twice");
      _data = TYPE_NONE;
    } else
      _u.i = _transp_proto;
    _transp_proto = UNKNOWN;
    if (_data != TYPE_NONE || _u.i == UNKNOWN)
      return errh->error("IP protocol missing in 'proto' directive");
    if (_u.i >= 256) {
      if (_op != OP_EQ || provided_mask)
	return errh->error("can't use relational operators or masks with '%s'", unparse_transp_proto(_u.i).c_str());
      _mask.u = 0xFF;
    } else if (set_mask(0xFF, 0, provided_mask, errh) < 0)
      return -1;
    if (_op == OP_EQ && _mask.u == 0xFF && !_op_negated) // set _transp_proto if allowed
      _transp_proto = _u.i;
    break;

   case TYPE_PORT:
    if (_data == TYPE_INT)
      _data = TYPE_PORT;
    if (_data != TYPE_PORT)
      return errh->error("port number missing in 'port' directive");
    if (_transp_proto == UNKNOWN)
      _transp_proto = IP_PROTO_TCP_OR_UDP;
    else if (_transp_proto != IP_PROTO_TCP && _transp_proto != IP_PROTO_UDP && _transp_proto != IP_PROTO_TCP_OR_UDP)
      return errh->error("bad protocol %d for 'port' directive", _transp_proto);
    if (set_mask(0xFFFF, 0, provided_mask, errh) < 0)
      return -1;
    break;

   case TYPE_TCPOPT:
    if (_data == TYPE_INT)
      _data = TYPE_TCPOPT;
    if (_data != TYPE_TCPOPT)
      return errh->error("TCP options missing in 'tcp opt' directive");
    if (_transp_proto == UNKNOWN)
      _transp_proto = IP_PROTO_TCP;
    else if (_transp_proto != IP_PROTO_TCP)
      return errh->error("bad protocol %d for 'tcp opt' directive", _transp_proto);
    if (_op != OP_EQ || _op_negated || provided_mask)
      return errh->error("can't use relational operators or masks with 'tcp opt'");
    if (_u.i < 0 || _u.i > 255)
      return errh->error("value %d out of range", _u.i);
    _mask.i = _u.i;
    break;

   case TYPE_IPECT:
     if (_data != TYPE_NONE && _data != TYPE_INT)
	 return errh->error("weird data given to 'ip ect' directive");
     if (_data == TYPE_NONE) {
	 _mask.u = IP_ECNMASK;
	 _u.u = 0;
	 _op_negated = true;
     }
     if (set_mask(0x3, 0, provided_mask, errh) < 0)
	 return -1;
     _type = FIELD_TOS;
     break;

   case TYPE_IPCE:
    if (_data != TYPE_NONE)
      return errh->error("'ip ce' directive takes no data");
    _mask.u = IP_ECNMASK;
    _u.u = IP_ECN_CE;
    _type = FIELD_TOS;
    break;

   case TYPE_IPFRAG:
    if (_data != TYPE_NONE)
      return errh->error("'ip frag' directive takes no data");
    _mask.u = 1; // don't want mask to be 0
    break;

   case TYPE_IPUNFRAG:
    if (_data != TYPE_NONE)
      return errh->error("'ip unfrag' directive takes no data");
    _op_negated = true;
    _mask.u = 1; // don't want mask to be 0
    _type = TYPE_IPFRAG;
    break;

   default:
    if (_type & TYPE_FIELD) {
      if (_data != TYPE_INT && _data != _type)
	return errh->error("value missing in '%s' directive", unparse_type().c_str());
      int nbits = ((_type & FIELD_LENGTH_MASK) >> FIELD_LENGTH_SHIFT) + 1;
      uint32_t mask = (nbits == 32 ? 0xFFFFFFFFU : (1 << nbits) - 1);
      if (set_mask(mask, 0, provided_mask, errh) < 0)
	return -1;
    }
    break;

  }

  // fix _srcdst
  if (_type == TYPE_HOST || _type == TYPE_PORT) {
    if (_srcdst == 0)
      _srcdst = SD_OR;
  } else if (old_srcdst)
    errh->warning("'src' or 'dst' is meaningless here");

  return 0;
}

static void
add_exprs_for_proto(int32_t proto, int32_t mask, Classifier *c, Vector<int> &tree)
{
  if (mask == 0xFF && proto == IP_PROTO_TCP_OR_UDP) {
    c->start_expr_subtree(tree);
    c->add_expr(tree, 8, htonl(IP_PROTO_TCP << 16), htonl(0x00FF0000));
    c->add_expr(tree, 8, htonl(IP_PROTO_UDP << 16), htonl(0x00FF0000));
    c->finish_expr_subtree(tree, Classifier::C_OR);
  } else if (mask == 0xFF && proto >= 256)
    /* nada */;
  else
    c->add_expr(tree, 8, htonl(proto << 16), htonl(mask << 16));
}

void
IPFilter::Primitive::add_comparison_exprs(Classifier *c, Vector<int> &tree, int offset, int shift, bool swapped, bool op_negate) const
{
  assert(_op == IPFilter::OP_EQ || _op == IPFilter::OP_GT);

  uint32_t mask = _mask.u;
  uint32_t u = _u.u & mask;
  if (swapped) {
    mask = ntohl(mask);
    u = ntohl(u);
  }

  if (_op == IPFilter::OP_EQ) {
    c->add_expr(tree, offset, htonl(u << shift), htonl(mask << shift));
    if (_op_negated && op_negate)
      c->negate_expr_subtree(tree);
    return;
  }

  // To implement a greater-than test for "input&MASK > U":
  // Check the top bit of U&MASK.
  // If the top bit is 0, then:
  //    Find TOPMASK, the top bits of MASK s.t. U&TOPMASK == 0.
  //    If "input&TOPMASK == 0", continue testing with lower bits of
  //    U and MASK; combine with OR.
  //    Otherwise, succeed.
  // If the top bit is 1, then:
  //    Find TOPMASK, the top bits of MASK s.t. (U+1)&TOPMASK == TOPMASK.
  //    If "input&TOPMASK == TOPMASK", continue testing with lower bits of
  //    U and MASK; combine with AND.
  //    Otherwise, fail.
  // Stop testing when U >= MASK.

  int high_bit_record = 0;
  int count = 0;

  while (u < mask) {
    int high_bit = (u > (mask >> 1));
    int first_different_bit = 33 - ffs_msb(high_bit ? ~(u+1) & mask : u);
    uint32_t upper_mask;
    if (first_different_bit == 33)
      upper_mask = mask;
    else
      upper_mask = mask & ~((1 << first_different_bit) - 1);
    uint32_t upper_u = (high_bit ? 0xFFFFFFFF & upper_mask : 0);

    c->start_expr_subtree(tree);
    c->add_expr(tree, offset, htonl(upper_u << shift), htonl(upper_mask << shift));
    if (!high_bit)
      c->negate_expr_subtree(tree);
    high_bit_record = (high_bit_record << 1) | high_bit;
    count++;

    mask &= ~upper_mask;
    u &= mask;
  }

  while (count > 0) {
    c->finish_expr_subtree(tree, (high_bit_record & 1 ? Classifier::C_AND : Classifier::C_OR));
    high_bit_record >>= 1;
    count--;
  }

  if (_op_negated && op_negate)
    c->negate_expr_subtree(tree);
}

void
IPFilter::Primitive::add_exprs(Classifier *c, Vector<int> &tree) const
{
  c->start_expr_subtree(tree);

  // enforce first fragment: fragmentation offset == 0
  // (before transport protocol to enhance later optimizations)
  if (_type == TYPE_PORT || _type == TYPE_TCPOPT || ((_type & TYPE_FIELD) && (_type & FIELD_PROTO_MASK)))
    c->add_expr(tree, 4, 0, htonl(0x00001FFF));

  // handle transport protocol uniformly
  if (_transp_proto != UNKNOWN)
    add_exprs_for_proto(_transp_proto, 0xFF, c, tree);

  // handle other types
  switch (_type) {

   case TYPE_HOST:
    c->start_expr_subtree(tree);
    if (_srcdst == SD_SRC || _srcdst == SD_AND || _srcdst == SD_OR)
      add_comparison_exprs(c, tree, 12, 0, true, false);
    if (_srcdst == SD_DST || _srcdst == SD_AND || _srcdst == SD_OR)
      add_comparison_exprs(c, tree, 16, 0, true, false);
    c->finish_expr_subtree(tree, (_srcdst == SD_OR ? C_OR : C_AND));
    if (_op_negated)
      c->negate_expr_subtree(tree);
    break;

   case TYPE_PROTO:
    if (_transp_proto < 256)
      add_comparison_exprs(c, tree, 8, 16, false, true);
    break;

   case TYPE_IPFRAG:
    c->add_expr(tree, 4, 0, htonl(0x00003FFF));
    if (!_op_negated)
      c->negate_expr_subtree(tree);
    break;

   case TYPE_PORT:
    c->start_expr_subtree(tree);
    if (_srcdst == SD_SRC || _srcdst == SD_AND || _srcdst == SD_OR)
      add_comparison_exprs(c, tree, TRANSP_FAKE_OFFSET, 16, false, false);
    if (_srcdst == SD_DST || _srcdst == SD_AND || _srcdst == SD_OR)
      add_comparison_exprs(c, tree, TRANSP_FAKE_OFFSET, 0, false, false);
    c->finish_expr_subtree(tree, (_srcdst == SD_OR ? C_OR : C_AND));
    if (_op_negated)
      c->negate_expr_subtree(tree);
    break;

   case TYPE_TCPOPT:
    c->add_expr(tree, TRANSP_FAKE_OFFSET + 12, htonl(_u.u << 16), htonl(_mask.u << 16));
    break;

   default:
    if (_type & TYPE_FIELD) {
      int offset = (_type & FIELD_OFFSET_MASK) >> FIELD_OFFSET_SHIFT;
      int length = ((_type & FIELD_LENGTH_MASK) >> FIELD_LENGTH_SHIFT) + 1;
      int word_offset = (offset >> 3) & ~3, bit_offset = offset & 0x1F;
      int transp_offset = (_type & FIELD_PROTO_MASK ? TRANSP_FAKE_OFFSET : 0);
      add_comparison_exprs(c, tree, transp_offset + word_offset, 32 - (bit_offset + length), false, true);
    } else
      assert(0);
    break;

  }

  c->finish_expr_subtree(tree);
}


static void
separate_text(const String &text, Vector<String> &words)
{
  const char* s = text.data();
  int len = text.length();
  int pos = 0;
  while (pos < len) {
    while (pos < len && isspace((unsigned char) s[pos]))
      pos++;
    switch (s[pos]) {

     case '&': case '|':
      if (pos < len - 1 && s[pos+1] == s[pos])
	goto two_char;
      goto one_char;

     case '<': case '>': case '!': case '=':
      if (pos < len - 1 && s[pos+1] == '=')
	goto two_char;
      goto one_char;

     case '(': case ')': case '[': case ']': case ',': case ';':
     case '?':
     one_char:
      words.push_back(text.substring(pos, 1));
      pos++;
      break;

     two_char:
      words.push_back(text.substring(pos, 2));
      pos += 2;
      break;

     default: {
	int first = pos;
	while (pos < len && (isalnum((unsigned char) s[pos]) || s[pos] == '-' || s[pos] == '.' || s[pos] == '/' || s[pos] == '@' || s[pos] == '_' || s[pos] == ':'))
	  pos++;
	if (pos == first)
	  pos++;
	words.push_back(text.substring(first, pos - first));
	break;
      }

    }
  }
}

/*
 * expr ::= orexpr
 *	|   orexpr ? expr : expr
 *	;
 * orexpr ::= orexpr || orexpr
 *	|   orexpr or orexpr
 *	|   term
 *	;
 * term ::= term && term
 *	|   term and term
 *	|   term factor			// juxtaposition = and
 *	|   term
 * factor ::= ! factor
 *	|   true
 *	|   false
 *	|   quals data
 *	|   quals relop data
 *	|   ( expr )
 *	;
 */

int
IPFilter::parse_expr(const Vector<String> &words, int pos,
		     Vector<int> &tree, Primitive &prev_prim,
		     ErrorHandler *errh)
{
  start_expr_subtree(tree);

  while (1) {
    pos = parse_orexpr(words, pos, tree, prev_prim, errh);
    if (pos >= words.size())
      break;
    if (words[pos] != "?")
      break;
    int old_pos = pos + 1;
    pos = parse_expr(words, old_pos, tree, prev_prim, errh);
    if (pos > old_pos && pos < words.size() && words[pos] == ":")
      pos++;
    else {
      errh->error("':' missing in ternary expression");
      break;
    }
  }

  finish_expr_subtree(tree, C_TERNARY);
  return pos;
}

int
IPFilter::parse_orexpr(const Vector<String> &words, int pos,
		     Vector<int> &tree, Primitive &prev_prim,
		     ErrorHandler *errh)
{
  start_expr_subtree(tree);

  while (1) {
    pos = parse_term(words, pos, tree, prev_prim, errh);
    if (pos >= words.size())
      break;
    if (words[pos] == "or" || words[pos] == "||")
      pos++;
    else
      break;
  }

  finish_expr_subtree(tree, C_OR);
  return pos;
}

int
IPFilter::parse_term(const Vector<String> &words, int pos,
		     Vector<int> &tree, Primitive &prev_prim,
		     ErrorHandler *errh)
{
  start_expr_subtree(tree);

  bool blank_ok = false;
  while (1) {
    int next = parse_factor(words, pos, tree, prev_prim, false, errh);
    if (next == pos)
      break;
    blank_ok = true;
    if (next < words.size() && (words[next] == "and" || words[next] == "&&")) {
      blank_ok = false;
      next++;
    }
    pos = next;
  }

  if (!blank_ok)
    errh->error("missing term");
  finish_expr_subtree(tree);
  return pos;
}

static int
parse_brackets(IPFilter::Primitive& prim, const Vector<String>& words, int pos,
	       ErrorHandler* errh)
{
  int first_pos = pos + 1;
  String combination;
  for (pos++; pos < words.size() && words[pos] != "]"; pos++)
    combination += words[pos];
  if (pos >= words.size()) {
    errh->error("missing ']'");
    return first_pos;
  }
  pos++;

  // parse 'combination'
  int fieldpos, len = 1;
  const char* colon = find(combination.begin(), combination.end(), ':');
  const char* comma = find(combination.begin(), combination.end(), ',');
  if (colon < combination.end() - 1) {
    if (cp_integer(combination.begin(), colon, 0, &fieldpos) == colon
	&& cp_integer(colon + 1, combination.end(), 0, &len) == combination.end())
      goto non_syntax_error;
  } else if (comma < combination.end() - 1) {
    int pos2;
    if (cp_integer(combination.begin(), comma, 0, &fieldpos) == comma
	&& cp_integer(comma + 1, combination.end(), 0, &pos2) == combination.end()) {
      len = pos2 - fieldpos + 1;
      goto non_syntax_error;
    }
  } else if (cp_integer(combination, &fieldpos))
    goto non_syntax_error;
  errh->error("syntax error after '[', expected '[POS]' or '[POS:LEN]'");
  return pos;

 non_syntax_error:
  int multiplier = 8;
  fieldpos *= multiplier, len *= multiplier;
  if (len < 1 || len > 32)
    errh->error("LEN in '[POS:LEN]' out of range, should be between 1 and 4");
  else if ((fieldpos & ~31) != ((fieldpos + len - 1) & ~31))
      errh->error("field [%d:%d] does not fit in a single word", fieldpos/multiplier, len/multiplier);
  else {
    int transp = prim._transp_proto;
    if (transp == IPFilter::UNKNOWN)
      transp = 0;
    prim.set_type(IPFilter::TYPE_FIELD
		  | (transp << IPFilter::FIELD_PROTO_SHIFT)
		  | (fieldpos << IPFilter::FIELD_OFFSET_SHIFT)
		  | ((len - 1) << IPFilter::FIELD_LENGTH_SHIFT), errh);
  }
  return pos;
}

int
IPFilter::parse_factor(const Vector<String> &words, int pos,
		       Vector<int> &tree, Primitive &prev_prim,
		       bool negated, ErrorHandler *errh)
{
  // return immediately on last word, ")", "||", "or", "?", ":"
  if (pos >= words.size() || words[pos] == ")" || words[pos] == "||" || words[pos] == "or" || words[pos] == "?" || words[pos] == ":")
    return pos;

  // easy cases

  // 'true' and 'false'
  if (words[pos] == "true") {
    add_expr(tree, 0, 0, 0);
    if (negated)
      negate_expr_subtree(tree);
    return pos + 1;
  }
  if (words[pos] == "false") {
    add_expr(tree, 0, 0, 0);
    if (!negated)
      negate_expr_subtree(tree);
    return pos + 1;
  }
  // ! factor
  if (words[pos] == "not" || words[pos] == "!") {
    int next = parse_factor(words, pos + 1, tree, prev_prim, !negated, errh);
    if (next == pos + 1)
      errh->error("missing factor after '%s'", words[pos].c_str());
    return next;
  }
  // ( expr )
  if (words[pos] == "(") {
    int next = parse_expr(words, pos + 1, tree, prev_prim, errh);
    if (next == pos + 1)
      errh->error("missing expression after '('");
    if (next >= 0) {
      if (next >= words.size() || words[next] != ")")
	errh->error("missing ')'");
      else
	next++;
      if (negated)
	negate_expr_subtree(tree);
    }
    return next;
  }

  // hard case

  // expect quals [relop] data
  int first_pos = pos;
  Primitive prim;

  // collect qualifiers
  for (; pos < words.size(); pos++) {
    String wd = words[pos];
    uint32_t wdata;
    int wt = lookup(wd, 0, UNKNOWN, wdata, 0);

    if (wt >= 0 && wt == TYPE_TYPE) {
      prim.set_type(wdata, errh);
      if ((wdata & TYPE_FIELD) && (wdata & FIELD_PROTO_MASK))
	prim.set_transp_proto((wdata & FIELD_PROTO_MASK) >> FIELD_PROTO_SHIFT, errh);

    } else if (wt >= 0 && wt == TYPE_PROTO)
      prim.set_transp_proto(wdata, errh);

    else if (wt != -1)
      break;

    else if (wd == "src") {
      if (pos < words.size() - 2 && (words[pos+2] == "dst" || words[pos+2] == "dest")) {
	if (words[pos+1] == "and" || words[pos+1] == "&&") {
	  prim.set_srcdst(SD_AND, errh);
	  pos += 2;
	} else if (words[pos+1] == "or" || words[pos+1] == "||") {
	  prim.set_srcdst(SD_OR, errh);
	  pos += 2;
	} else
	  prim.set_srcdst(SD_SRC, errh);
      } else
	prim.set_srcdst(SD_SRC, errh);
    } else if (wd == "dst" || wd == "dest")
      prim.set_srcdst(SD_DST, errh);

    else if (wd == "ip")
      /* nada */;

    else if (wd == "not" || wd == "!")
      negated = !negated;

    else
      break;
  }

  // prev_prim is not relevant if there were any qualifiers
  if (pos != first_pos)
    prev_prim.clear();

  // optional [] syntax
  String wd = (pos >= words.size() - 1 ? String() : words[pos]);
  if (wd == "[" && pos > first_pos && prim._type == TYPE_NONE) {
    pos = parse_brackets(prim, words, pos, errh);
    wd = (pos >= words.size() - 1 ? String() : words[pos]);
  }

  // optional bitmask
  uint32_t provided_mask = 0;
  if (wd == "&" && pos < words.size() - 1
      && cp_integer(words[pos + 1], &provided_mask)) {
      pos += 2;
      wd = (pos >= words.size() - 1 ? String() : words[pos]);
      if (provided_mask == 0)
	  errh->error("bitmask of 0 ignored");
  }

  // optional relational operation
  pos++;
  if (wd == "=" || wd == "==")
    /* nada */;
  else if (wd == "!=")
    prim._op_negated = true;
  else if (wd == ">")
    prim._op = OP_GT;
  else if (wd == "<")
    prim._op = OP_LT;
  else if (wd == ">=") {
    prim._op = OP_LT;
    prim._op_negated = true;
  } else if (wd == "<=") {
    prim._op = OP_GT;
    prim._op_negated = true;
  } else
    pos--;

  // now collect the actual data
  if (pos < words.size()) {
    wd = words[pos];
    uint32_t wdata;
    int wt = lookup(wd, prim._type, prim._transp_proto, wdata, errh);
    pos++;

    if (wt == -2)		// ambiguous or incorrect word type
      /* absorb word, but do nothing */
      prim._type = -2;

    else if (wt != -1 && wt != TYPE_TYPE) {
      prim._data = wt;
      prim._u.u = wdata;

    } else if (cp_integer(wd, &prim._u.i))
      prim._data = TYPE_INT;

    else if (cp_ip_address(wd, prim._u.c, this)) {
      if (pos < words.size() - 1 && words[pos] == "mask"
	  && cp_ip_address(words[pos+1], prim._mask.c, this)) {
	pos += 2;
	prim._data = TYPE_NET;
      } else if (prim._type == TYPE_NET && cp_ip_prefix(wd, prim._u.c, prim._mask.c, this))
	prim._data = TYPE_NET;
      else
	prim._data = TYPE_HOST;

    } else if (cp_ip_prefix(wd, prim._u.c, prim._mask.c, this))
      prim._data = TYPE_NET;

    else {
      if (prim._op != OP_EQ || prim._op_negated)
	errh->error("dangling operator near '%s'", wd.c_str());
      pos--;
    }
  }

  if (pos == first_pos) {
    errh->error("empty term near '%s'", wd.c_str());
    return pos;
  }

  // add if it is valid
  if (prim.check(prev_prim, provided_mask, errh) >= 0) {
    prim.add_exprs(this, tree);
    if (negated)
      negate_expr_subtree(tree);
    prev_prim = prim;
  }

  return pos;
}

int
IPFilter::configure(Vector<String> &conf, ErrorHandler *errh)
{
  int before_nerrors = errh->nerrors();
  _output_everything = -1;

  // requires packet headers be aligned
  _align_offset = 0;

  Vector<int> tree;
  init_expr_subtree(tree);

  // [QUALS] [host|net|port|proto] [data]
  // QUALS ::= src | dst | src and dst | src or dst | \empty
  //        |  ip | icmp | tcp | udp
  for (int argno = 0; argno < conf.size(); argno++) {
    Vector<String> words;
    separate_text(cp_unquote(conf[argno]), words);

    if (words.size() == 0) {
      errh->error("empty pattern %d", argno);
      continue;
    }

    PrefixErrorHandler cerrh(errh, "pattern " + String(argno) + ": ");

    // get slot
    int slot = noutputs();
    {
      String slotwd = words[0];
      if (slotwd == "allow") {
	slot = 0;
	if (noutputs() == 0)
	  cerrh.error("'allow' is meaningless, element has zero outputs");
      } else if (slotwd == "deny") {
	slot = noutputs();
	if (noutputs() > 1)
	  cerrh.warning("meaning of 'deny' has changed (now it means 'drop')");
      } else if (slotwd == "drop")
	slot = noutputs();
      else if (cp_integer(slotwd, &slot)) {
	if (slot < 0 || slot >= noutputs()) {
	  cerrh.error("slot '%d' out of range", slot);
	  slot = noutputs();
	}
      } else
	cerrh.error("unknown slot ID '%s'", slotwd.c_str());
    }

    start_expr_subtree(tree);

    // check for "-"
    if (words.size() == 1 || (words.size() == 2 && words[1] == "-")
	|| (words.size() == 2 && words[1] == "any")
	|| (words.size() == 2 && words[1] == "all"))
      add_expr(tree, 0, 0, 0);

    else {
      // start with a blank primitive
      Primitive prev_prim;

      int pos = parse_expr(words, 1, tree, prev_prim, &cerrh);
      if (pos < words.size())
	cerrh.error("garbage after expression at '%s'", words[pos].c_str());
    }

    finish_expr_subtree(tree, C_AND, -slot);
  }

  if (tree.size())
    finish_expr_subtree(tree, C_OR, -noutputs(), -noutputs());

  //{ String sxx = program_string(this, 0); click_chatter("%s", sxx.c_str()); }
  optimize_exprs(errh);

  // Compress the program into _prog.
  // It helps to do another bubblesort for things like ports.
  bubble_sort_and_exprs();
  compress_exprs(_prog, PERFORM_BINARY_SEARCH, MIN_BINARY_SEARCH);

  //{ String sxx = program_string(this, 0); click_chatter("%s", sxx.c_str()); }
  return (errh->nerrors() == before_nerrors ? 0 : -1);
}

#if CLICK_USERLEVEL
String
IPFilter::compressed_program_string(Element *e, void *)
{
    IPFilter *c = static_cast<IPFilter *>(e);
    const Vector<uint32_t> &prog = c->_prog;

    StringAccum sa;
    for (int i = 0; i < prog.size(); ) {
	sa.snprintf(80, "%3d %3d/%08x%%%08x  yes->", i, (uint16_t) prog[i], htonl(prog[i+4]), htonl(prog[i+3]));
	if ((int32_t) prog[i+2] > 0)
	    sa << "step " << (prog[i+2] + i);
	else
	    sa << "[" << -((int32_t) prog[i+2]) << "]";
	if ((int32_t) prog[i+1] > 0)
	    sa << "  no->step " << (prog[i+1] + i);
	else
	    sa << "  no->[" << -((int32_t) prog[i+1]) << "]";
	sa << "\n";
	for (unsigned x = 1; x < (prog[i] >> 16); ++x)
	    sa.snprintf(80, "        %08x\n", htonl(prog[i+4+x]));
	i += (prog[i] >> 16) + 4;
    }
    if (prog.size() == 0)
	sa << "all->[" << c->_output_everything << "]\n";
    sa << "safe length " << c->_safe_length << "\n";
    sa << "alignment offset " << c->_align_offset << "\n";
    return sa.take_string();
}
#endif

void
IPFilter::add_handlers()
{
    Classifier::add_handlers();
#if CLICK_USERLEVEL
    add_read_handler("compressed_program", compressed_program_string, 0);
#endif
}


//
// RUNNING
//

void
IPFilter::length_checked_push(Packet *p)
{
  const unsigned char *neth_data = p->network_header();
  const unsigned char *transph_data = p->transport_header();
  int packet_length = p->length() + TRANSP_FAKE_OFFSET - p->transport_header_offset();
  const uint32_t *pr = _prog.begin();
  const uint32_t *pp;
  uint32_t data = 0;

  while (1) {
      int off = (int16_t) pr[0];
      if (off + 4 > packet_length)
	  goto check_length;

    length_ok:
      if (off >= TRANSP_FAKE_OFFSET)
	  data = *(const uint32_t *)(transph_data + off - TRANSP_FAKE_OFFSET);
      else
	  data = *(const uint32_t *)(neth_data + off);
      data &= pr[3];
      off = pr[0] >> 16;
      pp = pr + 4;
      if (!PERFORM_BINARY_SEARCH || off < MIN_BINARY_SEARCH) {
	  for (; off; --off, ++pp)
	      if (*pp == data) {
		  off = pr[2];
		  goto gotit;
	      }
      } else {
	  const uint32_t *px = pp + off;
	  while (pp < px) {
	      const uint32_t *pm = pp + (px - pp) / 2;
	      if (*pm == data) {
		  off = pr[2];
		  goto gotit;
	      } else if (*pm < data)
		  pp = pm + 1;
	      else
		  px = pm;
	  }
      }
    failure:
      off = pr[1];
    gotit:
      if (off <= 0) {
	  checked_output_push(-off, p);
	  return;
      }
      pr += off;
      continue;

    check_length:
      if (off < packet_length) {
	  unsigned available = packet_length - off;
	  const uint8_t *c = (const uint8_t *) &pr[3];
	  if (!(c[3]
		|| (c[2] && available <= 2)
		|| (c[1] && available == 1)))
	      goto length_ok;
      }
      goto failure;
  }
}

void
IPFilter::push(int, Packet *p)
{
  const unsigned char *neth_data = p->network_header();
  const unsigned char *transph_data = p->transport_header();

  if (_output_everything >= 0) {
    // must use checked_output_push because the output number might be
    // out of range
    checked_output_push(_output_everything, p);
    return;
  } else if (p->length() + TRANSP_FAKE_OFFSET - p->transport_header_offset() < _safe_length) {
    // common case never checks packet length
    length_checked_push(p);
    return;
  }

  const uint32_t *pr = _prog.begin();
  const uint32_t *pp;
  uint32_t data;
  while (1) {
      int off = (int16_t) pr[0];
      if (off >= TRANSP_FAKE_OFFSET)
	  data = *(const uint32_t *)(transph_data + off - TRANSP_FAKE_OFFSET);
      else
	  data = *(const uint32_t *)(neth_data + off);
      data &= pr[3];
      off = pr[0] >> 16;
      pp = pr + 4;
      if (!PERFORM_BINARY_SEARCH || off < MIN_BINARY_SEARCH) {
	  for (; off; --off, ++pp)
	      if (*pp == data) {
		  off = pr[2];
		  goto gotit;
	      }
      } else {
	  const uint32_t *px = pp + off;
	  while (pp < px) {
	      const uint32_t *pm = pp + (px - pp) / 2;
	      if (*pm == data) {
		  off = pr[2];
		  goto gotit;
	      } else if (*pm < data)
		  pp = pm + 1;
	      else
		  px = pm;
	  }
      }
      off = pr[1];
    gotit:
      if (off <= 0) {
	  checked_output_push(-off, p);
	  return;
      }
      pr += off;
  }
}

CLICK_ENDDECLS
ELEMENT_REQUIRES(Classifier)
EXPORT_ELEMENT(IPFilter)
