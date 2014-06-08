(ns bitcoin-protocol.messages_test
  (:use midje.sweet)
  (:require [bitcoin-protocol.messages :as pm]
            [gloss.io :refer :all]))

(defn- str-bytes [h]
  (clojure.string/trimr
   (apply str
          (for [x (range (.remaining h))]
            (format "%02X " (.get h x))))))

(fact "Varint encoding seems to work"
      (str-bytes (first (encode pm/varint 0x05))) => "05"
      (str-bytes (first (encode pm/varint 0x32))) => "32"
      (str-bytes (first (encode pm/varint 0xFC))) => "FC"                  
      (str-bytes (first (encode pm/varint 0xFD))) => "FD FD 00"            
      (str-bytes (first (encode pm/varint 0xFF))) => "FD FF 00"      
      (str-bytes (first (encode pm/varint 0xFFFE))) => "FD FE FF"
      (str-bytes (first (encode pm/varint 0xFFFF))) => "FD FF FF"
      (str-bytes (first (encode pm/varint 0x10000))) => "FE 00 00 01 00"
      (str-bytes (first (encode pm/varint 0x100000))) => "FE 00 00 10 00"
      (str-bytes (first (encode pm/varint 0xFFFFFFFF))) => "FE FF FF FF FF"
      (str-bytes (first (encode pm/varint 0x100000000))) => "FF 00 00 00 00 01 00 00 00"
      (str-bytes (first (encode pm/varint 0xFFFFFFFFFF))) => "FF FF FF FF FF FF 00 00 00")

(let [[satoshi-varint satoshi-str] (encode pm/varstr "/Satoshi:0.7.2/")]
  (facts "Varstr encoding seems to work"
         (fact "Length of \"/Satoshi:0.7.2/\" is 15"
               (str-bytes satoshi-varint) => "0F")
         (fact "Char array of \"/Satoshi:0.7.2/\" is correct"
               (str-bytes satoshi-str) => "2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F")))

(defn expected-bytes [length]
  (+ (dec length)
     (* 2 length)))

(let [[nettime
       services
       ip
       port]
      (map str-bytes (encode pm/net-addrt
                             [1
                              1
                              "192.168.1.1"
                              0xFF]))]
  (facts "Netaddrt seems to work"
         (facts "Timestamp"
                (fact "4 bytes in timestamp"
                      (count nettime) => (expected-bytes 4))
                (fact "Timestamp example encoded as expected (4 byte Little Endian)"
                      nettime => "01 00 00 00"))
         (facts "Services"
                (fact "8 bytes in services"
                      (count services) => (expected-bytes 8))
                (fact "Services example encoded as expected (8 byte Little Endian)"
                      services => "01 00 00 00 00 00 00 00"))))


(facts "Checksum seems to work"
       (fact "First four bytes of hello double SHA-256 is '95 95 C9 DF'"
             ;; hello
             ;; 2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824 (first round of sha-256)
             ;; 9595c9df90075148eb06860365df33584b75bff782a510c6cd4883a419833d50 (second round of sha-256)
             (str-bytes (first (encode pm/checksum (pm/gen-checksum (.getBytes "hello")))))
             => "95 95 C9 DF"))


(facts "Version payload seems to work"
       (fact "Personal example works"
             (->> [1 1 1 [5 5 "125.165.1.1" 8080] [5 15 "125.165.1.1" 8080] 5 "hi" 5 true]
                  (encode pm/version-payload)
                  (map str-bytes)) => '("01 00 00 00"
                                        "01 00 00 00 00 00 00 00"
                                        "01 00 00 00 00 00 00 00"
                                        "05 00 00 00"
                                        "05 00 00 00 00 00 00 00"
                                        "00 00 00 00 00 00 00 00 00 00 FF FF 7D A5 01 01"
                                        "90 1F"
                                        "05 00 00 00"
                                        "0F 00 00 00 00 00 00 00"
                                        "00 00 00 00 00 00 00 00 00 00 FF FF 7D A5 01 01"
                                        "90 1F"
                                        "05 00 00 00 00 00 00 00"
                                        "02"
                                        "68 69"
                                        "05 00 00 00"
                                        "01"))
       
       (fact "Example 1"

             ;; 0000   f9 be b4 d9 76 65 72 73 69 6f 6e 00 00 00 00 00  ....version.....
             ;; 0010   64 00 00 00 35 8d 49 32 62 ea 00 00 01 00 00 00  d...5.I2b.......
             ;; 0020   00 00 00 00 11 b2 d0 50 00 00 00 00 01 00 00 00  .......P........
             ;; 0030   00 00 00 00 00 00 00 00 00 00 00 00 00 00 ff ff  ................
             ;; 0040   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00  ................
             ;; 0050   00 00 00 00 00 00 00 00 ff ff 00 00 00 00 00 00  ................
             ;; 0060   3b 2e b3 5d 8c e6 17 65 0f 2f 53 61 74 6f 73 68  ;..]...e./Satosh
             ;; 0070   69 3a 30 2e 37 2e 32 2f c0 3e 03 00              i:0.7.2/.>..

             ;; Message Header:
             ;; F9 BE B4 D9                                                                   - Main network magic bytes
             ;; 76 65 72 73 69 6F 6E 00 00 00 00 00                                           - "version" command
             ;; 64 00 00 00                                                                   - Payload is 100 bytes long
             ;; 3B 64 8D 5A                                                                   - payload checksum

             ;; Version message:
             ;; 62 EA 00 00                                                                   - 60002 (protocol version 60002)
             ;; 01 00 00 00 00 00 00 00                                                       - 1 (NODE_NETWORK services)
             ;; 11 B2 D0 50 00 00 00 00                                                       - Tue Dec 18 10:12:33 PST 2012
             ;; 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00 - Recipient address info - see Network Address
             ;; 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00 - Sender address info - see Network Address
             ;; 3B 2E B3 5D 8C E6 17 65                                                       - Node ID
             ;; 0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F                               - "/Satoshi:0.7.2/" sub-version string (string is 15 bytes long)
             ;; C0 3E 03 00                                                                   - Last block sending node has is block #212672
             
             (->> [60002 1 1355854353 [1 0 "0.0.0.0" 0] [1 0 "0.0.0.0" 0] 7284544412836900411 "/Satoshi:0.7.2/" 212672 true]
                  (encode pm/version-payload)
                  (map str-bytes)) => '("62 EA 00 00"
                                        "01 00 00 00 00 00 00 00"
                                        "11 B2 D0 50 00 00 00 00"
                                        "01 00 00 00"
                                        "00 00 00 00 00 00 00 00"
                                        "00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00"
                                        "00 00"
                                        "01 00 00 00"
                                        "00 00 00 00 00 00 00 00"
                                        "00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00"
                                        "00 00"
                                        "3B 2E B3 5D 8C E6 17 65"
                                        "0F"
                                        "2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F"
                                        "C0 3E 03 00"
                                        "01")))
