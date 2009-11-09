#ifndef CLICK_IPRWPATTERNS_HH
#define CLICK_IPRWPATTERNS_HH
#include "elements/ip/iprw.hh"
#include <click/hashmap.hh>
CLICK_DECLS

/*
 * =c
 * IPRewriterPatterns(NAME PATTERN, ...)
 * =s nat
 * specifies shared IPRewriter(n) patterns
 * =d
 *
 * This element stores information about shared patterns that IPRewriter and
 * related elements can use.  Each configuration argument is a name and a
 * pattern, 'NAME SADDR SPORT DADDR DPORT'.  The NAMEs for every argument in
 * every IPRewriterPatterns element in the configuration must be distinct.
 *
 * =a IPRewriter
 */

class IPRewriterPatterns : public Element {

  HashTable<String, int> _name_map;
  Vector<IPRw::Pattern *> _patterns;

 public:

  IPRewriterPatterns();
  ~IPRewriterPatterns();

  const char *class_name() const	{ return "IPRewriterPatterns"; }

  int configure_phase() const	{ return IPRw::CONFIGURE_PHASE_PATTERNS; }
  int configure(Vector<String> &, ErrorHandler *);
  void cleanup(CleanupStage);

  static IPRw::Pattern *find(Element *, const String &, ErrorHandler *);

};

CLICK_ENDDECLS
#endif
