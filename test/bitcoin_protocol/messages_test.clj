(ns bitcoin-protocol.messages_test
  (:require [clojure.test :refer :all]
            [bitcoin-protocol.messages :as pm]
            [gloss.io :refer :all]))

(defn- str-bytes [h]
  (clojure.string/trimr
   (apply str
          (for [x (range (.remaining h))]
            (format "%02X " (.get h x))))))

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

(deftest raw-varstr-encoding
  (let [[satoshi-varint satoshi-str] (encode pm/varstr "/Satoshi:0.7.2/")]
    ;; Length of "/Satoshi:0.7.2/" is 15
    (is (= (str-bytes satoshi-varint) "0F"))
    ;; Char array of "/Satoshi:0.7.2/" is correct
    (is (= (str-bytes satoshi-str) "2F 53 61 74 6F 73 68 69 3A 30 2E 37 2E 32 2F"))))

(deftest raw-netaddrt-encoding
  (let [[nettime
         services
         ip
         port]
        (map str-bytes (encode pm/net-addrt
                               [1
                                1
                                "192.168.1.1"
                                0xFF]))]
    ;; Timestamp
    ;; 4 bytes in timestamp
    (is (= (count nettime) (expected-bytes 4)))
    ;; Timestamp example encoded as expected (4 byte Little Endian)
    (is (= nettime "01 00 00 00"))
    ;; Services
    ;; 8 bytes in services
    (is (= (count services) (expected-bytes 8)))
    ;; Services example encoded as expected (8 byte Little Endian)
    (is (= services "01 00 00 00 00 00 00 00"))))

(deftest raw-checksum
  ;; First four bytes of hello double SHA-256 is '95 95 C9 DF'
  (is (= (-> pm/checksum
             (encode (->> "hello"
                          .getBytes
                          pm/gen-checksum))
             first
             str-bytes)
         "95 95 C9 DF")))


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

  (is (= (->> {:version 60002 :services 1 :timestamp 1355854353 :addr-recv [1 "0.0.0.0" 0] :addr-from [1 "0.0.0.0" 0] :nonce 7284544412836900411 :user-agent "/Satoshi:0.7.2/" :start-height 212672 :relay true}
              (encode pm/version-payload)
              (map str-bytes))
         '("62 EA 00 00"
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
           "01"))))

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

  
  (= (map str-bytes (encode pm/bitcoin-network-message
                            {:command "version"
                             :magic :magic-value
                             :version 60001
                             :services 1
                             :timestamp 0x50D0B211
                             :addr-recv [1 "0.0.0.0" 0]
                             :addr-from [1 "0.0.0.0" 0]
                             :nonce 0x6517E68C5DB32E3B
                             :user-agent "/Satoshi:0.7.2/"
                             :start-height 212672
                             :relay true}))
     '("F9 BE B4 D9"
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
       "01")))

(deftest verack-message
  ;; Message header:
  ;;  F9 BE B4 D9                          - Main network magic bytes
  ;;  76 65 72 61  63 6B 00 00 00 00 00 00 - "verack" command
  ;;  00 00 00 00                          - Payload is 0 bytes long
  ;;  5D F6 E0 E2                          - Checksum  
  (is (= (map str-bytes (encode pm/bitcoin-network-message
                                {:magic :magic-value
                                 :command "verack"}))
         '("F9 BE B4 D9" 
           "76 65 72 61 63 6B 00 00 00 00 00 00"
           "00"
           "5D F6 E0 E2"))))


(deftest addr-message
  (is (= (map str-bytes (encode pm/bitcoin-network-message {:magic :magic-value
                                                            :command "addr"
                                                            :payload [[0x4D1015E2 1 "10.0.0.1" 8333]]}))
         '("F9 BE B4 D9"
           "61 64 64 72 00 00 00 00 00 00 00 00"
           "1F"
           "ED 52 39 9B"
           "01"
           "E2 15 10 4D"
           "01 00 00 00 00 00 00 00"
           "00 00 00 00 00 00 00 00 00 00 FF FF 0A 00 00 01"
           "20 8D"))))






