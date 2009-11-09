FromDevice(ath0) 
-> RadiotapDecap() -> -> GetIPAddress(16) -> rt;
  rt :: LinearIPLookup(0);
  rt[0] -> Discard;
  rt[1] -> RogueDetect() -> Discard;

//-> wifi_cl :: Classifier(0/08%0c 1/01%03, //data
//			 0/00%0c); //mgt
//
//wifi_cl [1] -> mgt_cl :: Classifier(0/00%f0, //assoc req
//				    0/10%f0, //assoc resp
//				    0/40%f0, //probe req
//				    0/50%f0, //probe resp
//				    0/80%f0, //beacon
//				    0/a0%f0, //disassoc
//				    0/b0%f0, //disassoc
//				    );
//

