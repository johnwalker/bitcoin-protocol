(ns bitcoin-protocol.messages_test
  (:use midje.sweet)
  (:require [bitcoin-protocol.messages :as pm]
            [gloss.io :refer :all]))

(defn- str-bytes [h]
  (clojure.string/trimr
   (apply str
          (for [x (range (.remaining h))]
            (format "%02X " (.get h x))))))

(fact "Varint encoding works according to https://en.bitcoin.it/wiki/Protocol_specification#Variable_length_integer"
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
