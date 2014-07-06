(ns bitcoin-protocol.messages_test
  (:require [clojure.test :refer :all]
            [clojure.test.check :as tc]
            [clojure.test.check.clojure-test :refer [defspec]]
            [clojure.test.check.generators :as gen]
            [clojure.test.check.properties :as prop]
            [bitcoin-protocol.messages :as pm]
            [gloss.io :refer :all]))

(defn- str-bytes [h]
  (clojure.string/trimr
   (apply str
          (for [x (range (.remaining h))]
            (format "%02X " (.get h x))))))

(defn to-unsigned [x]
  (bit-and x 0xFF))

(defn expected-bytes [length]
  (+ (dec length)
     (* 2 length)))

(deftest raw-varint-encoding
  (is (= (str-bytes (first (encode pm/varint 0x05))) "05"))
  (is (= (str-bytes (first (encode pm/varint 0x32))) "32"))
  (is (= (str-bytes (first (encode pm/varint 0xFC))) "FC"))
  (is (= (str-bytes (first (encode pm/varint 0xFD))) "FD FD 00"))
  (is (= (str-bytes (first (encode pm/varint 0xFF))) "FD FF 00"))
  (is (= (str-bytes (first (encode pm/varint 0xFFFE))) "FD FE FF"))
  (is (= (str-bytes (first (encode pm/varint 0xFFFF))) "FD FF FF"))
  (is (= (str-bytes (first (encode pm/varint 0x10000))) "FE 00 00 01 00"))
  (is (= (str-bytes (first (encode pm/varint 0x100000))) "FE 00 00 10 00"))
  (is (= (str-bytes (first (encode pm/varint 0xFFFFFFFF))) "FE FF FF FF FF"))
  (is (= (str-bytes (first (encode pm/varint 0x100000000))) "FF 00 00 00 00 01 00 00 00"))
  (is (= (str-bytes (first (encode pm/varint 0xFFFFFFFFFF))) "FF FF FF FF FF FF 00 00 00")))


(defspec isomorphic-varint
  150
  (prop/for-all [i gen/pos-int]
                (= i (decode pm/varint (encode pm/varint i)))))


(deftest raw-varstr-encoding
  (let [[satoshi-varint satoshi-str] (encode pm/varstr "/Satoshi:0.7.2/")]
    ;; Length of "/Satoshi:0.7.2/" is 15
    (is (= (str-bytes satoshi-varint) "0F"))
    ;; Char array of "/Satoshi:0.7.2/" is correct
    (is (= (str-bytes satoshi-str) "2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F"))))


(defspec isomorphic-varstr
  150
  (prop/for-all [s gen/string-ascii]
                (= s (decode pm/varstr (encode pm/varstr s)))))


(defspec isomorphic-ipaddr
  150
  (prop/for-all [ip (gen/vector gen/byte 4)]
                (let [ubv (mapv to-unsigned ip)
                      ip-str (apply str (interpose "." ubv))]
                  (= ip-str (decode pm/ip-addr (encode pm/ip-addr ip-str))))))


(deftest raw-netaddrt-encoding
  (= (apply str-bytes (encode pm/net-addrt
                              {:time 1
                               :services 1
                               :ip "192.168.1.1"
                               :port 0xFF}))
     "01 00 00 00 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF C0 A8 01 01 00 FF"))

(defspec isomorphic-netaddrt
  150
  (prop/for-all [ip (gen/vector gen/byte 4)
                 i gen/pos-int
                 j gen/pos-int
                 k gen/byte]
                (let [ubv (mapv to-unsigned ip)
                      ip-str (apply str (interpose "." ubv))
                      k (to-unsigned k)]
                  (= {:time i
                      :services j
                      :ip ip-str
                      :port k}
                     (decode pm/net-addrt (encode pm/net-addrt {:time i
                                                                :services j
                                                                :ip ip-str
                                                                :port k}))))))

(deftest raw-checksum
  ;; First four bytes of hello double SHA-256 is '95 95 C9 DF'
  (is (= (-> pm/checksum
             (encode (->> "hello"
                          .getBytes
                          (pm/gen-checksum 4)))
             first
             str-bytes)
         "95 95 C9 DF")))


(defspec isomorphic-checksum
  150
  (prop/for-all [i (gen/vector gen/byte 4)]
                (let [ubv (mapv to-unsigned i)]
                  (= ubv (decode pm/checksum (encode pm/checksum ubv))))))


(deftest version-payload
  ;; Example #1 on Wiki (with relay codec appended to end)
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

  (is (= (->> {:version 60002 :services 1 :timestamp 1355854353
               :addr-recv {:services 1
                           :ip "0.0.0.0"
                           :port 0}
               :addr-from {:services 1
                           :ip "0.0.0.0"
                           :port 0}
               :nonce 7284544412836900411
               :user-agent "/Satoshi:0.7.2/"
               :start-height 212672
               :relay true}
              (encode pm/version-payload)
              (map str-bytes)
              (interpose " ")
              (apply str))
         (apply str (interpose " " '("62 EA 00 00"
                                     "01 00 00 00 00 00 00 00"
                                     "11 B2 D0 50 00 00 00 00"
                                     "01 00 00 00 00 00 00 00"
                                     "00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00"
                                     "01 00 00 00 00 00 00 00"
                                     "00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00"
                                     "3B 2E B3 5D 8C E6 17 65"
                                     "0F"
                                     "2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F"
                                     "C0 3E 03 00"
                                     "01"))))))


(deftest version-message
  ;; NOTE: There just happens to be a collision between these two
  ;; examples. This is a version without the relay byte.

  ;;  F9 BE B4 D9                                                                   - Main network magic bytes
  ;;  76 65 72 73 69 6F 6E 00 00 00 00 00                                           - "version" command
  ;;  64 00 00 00                                                                   - Payload is 100 bytes long
  ;;  3B 64 8D 5A                                                                   - payload checksum

  ;; Version message:
  ;;  62 EA 00 00                                                                   - 60002 (protocol version 60002)
  ;;  01 00 00 00 00 00 00 00                                                       - 1 (NODE_NETWORK services)
  ;;  11 B2 D0 50 00 00 00 00                                                       - Tue Dec 18 10:12:33 PST 2012
  ;;  01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00 - Recipient address info - see Network Address
  ;;  01 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00 00 00 - Sender address info - see Network Address
  ;;  3B 2E B3 5D 8C E6 17 65                                                       - Node ID
  ;;  0F 2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F                               - "/Satoshi:0.7.2/" sub-version string (string is 15 bytes long)
  ;;  C0 3E 03 00                                                                   - Last block sending node has is block #212672


  (= (apply str (interpose " " (map str-bytes (encode pm/bitcoin-network-message
                                                      {:command "version"
                                                       :magic :main
                                                       :version 60001
                                                       :services 1
                                                       :timestamp 0x50D0B211
                                                       :addr-recv {:services 1 :ip "0.0.0.0" :port 0}
                                                       :addr-from {:services 1 :ip "0.0.0.0" :port 0}
                                                       :nonce 0x6517E68C5DB32E3B
                                                       :user-agent "/Satoshi:0.7.2/"
                                                       :start-height 212672
                                                       :relay true}))))
     (apply str (interpose " " '("F9 BE B4 D9"
                                 "76 65 72 73 69 6F 6E 00 00 00 00 00"
                                 "65"
                                 "85 27 39 E3"
                                 "61 EA 00 00"
                                 "01 00 00 00 00 00 00 00"
                                 "11 B2 D0 50 00 00 00 00"
                                 "01 00 00 00 00 00 00 00"
                                 "00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00"
                                 "00 00"
                                 "01 00 00 00 00 00 00 00"
                                 "00 00 00 00 00 00 00 00 00 00 FF FF 00 00 00 00"
                                 "00 00"
                                 "3B 2E B3 5D 8C E6 17 65"
                                 "0F"
                                 "2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F"
                                 "C0 3E 03 00"
                                 "01")))))


(deftest verack-message
  ;; Message header:
  ;;  F9 BE B4 D9                          - Main network magic bytes
  ;;  76 65 72 61  63 6B 00 00 00 00 00 00 - "verack" command
  ;;  00 00 00 00                          - Payload is 0 bytes long
  ;;  5D F6 E0 E2                          - Checksum
  (is (= (map str-bytes (encode pm/bitcoin-network-message
                                {:magic :main
                                 :command "verack"}))
         '("F9 BE B4 D9"
           "76 65 72 61 63 6B 00 00 00 00 00 00"
           "00"
           "5D F6 E0 E2"))))


(deftest addr-message
  (is (= (apply str (interpose " " (map str-bytes (encode pm/bitcoin-network-message {:magic :main
                                                                                      :command "addr"
                                                                                      :payload [{:time 0x4D1015E2 :services 1 :ip "10.0.0.1" :port 8333}]}))))
         (apply str (interpose " " '("F9 BE B4 D9"
                                     "61 64 64 72 00 00 00 00 00 00 00 00"
                                     "1F"
                                     "ED 52 39 9B"
                                     "01"
                                     "E2 15 10 4D"
                                     "01 00 00 00 00 00 00 00"
                                     "00 00 00 00 00 00 00 00 00 00 FF FF 0A 00 00 01"
                                     "20 8D"))))))
