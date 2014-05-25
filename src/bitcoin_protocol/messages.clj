(ns bitcoin-protocol.messages 
  (:require [gloss.core :refer :all]
            [gloss.io :refer :all]))

(defcodec varint (header :ubyte
                         (fn [h]
                           (compile-frame
                            (case h
                              0xfd :uint16-le
                              0xfe :uint32-le
                              0xff :uint64-le
                              (compile-frame nil-frame
                                             identity
                                             (fn [_] h)))))
                         (fn [b]
                           (condp >= b
                             0xfc b
                             0xffff 0xfd
                             0xffffffff 0xfe
                             0xff))))

(defcodec varstr (finite-frame
                  varint
                  (string :ascii)))

(defcodec ip-addr (compile-frame (repeated :ubyte :prefix :none)
                                 (fn [s]
                                   (concat (repeat 10 0)
                                           (repeat 2 0xFF)
                                           (map
                                            #(Integer/parseInt %)
                                            (clojure.string/split s #"\."))))
                                 (fn [b]
                                   (apply str (interpose "." (take-last 4 b)))))) 
(defcodec net-addrt (compile-frame [:uint32-le
                                    :uint64-le
                                    ip-addr
                                    :uint16-le]))
