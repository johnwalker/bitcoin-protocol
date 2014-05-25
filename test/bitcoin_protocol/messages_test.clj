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

