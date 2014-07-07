(ns bitcoin-protocol.messages
  (:require [bitcoin-protocol.gloss.extension :as e]
            [clojure.string :as str]
            [gloss.core :refer :all]
            [gloss.io :refer :all]))


(let [u16-le (compile-frame :uint16-le)
      u32-le (compile-frame :uint32-le)
      u64-le (compile-frame :uint64-le)]
  (defcodec varint (header :ubyte
                           (fn [h]
                             (case h
                               0xfd u16-le
                               0xfe u32-le
                               0xff u64-le
                               (compile-frame nil-frame
                                              identity
                                              (constantly h))))
                           (fn [b]
                             (condp >= b
                               0xfc b
                               0xffff 0xfd
                               0xffffffff 0xfe
                               0xff)))))


(defcodec varstr (compile-frame (finite-frame
                                 varint
                                 (string :ascii))
                                identity
                                (fn [s]
                                  (or s ""))))


(defcodec ip-addr (compile-frame (repeat 16 :ubyte)
                                 (fn [s]
                                   (concat (repeat 10 0)
                                           (repeat 2 0xFF)
                                           (map
                                            #(Integer/parseInt %)
                                            (str/split s #"\."))))
                                 (fn [b]
                                   (apply str (interpose "." (take-last 4 b))))))

(defcodec net-addr (ordered-map
                    :services :uint64-le
                    :ip ip-addr
                    :port :uint16-be))


(defcodec net-addrt (ordered-map :time :uint32-le
                                 :services :uint64-le
                                 :ip ip-addr
                                 :port :uint16-be))


(defcodec magic (enum :uint32-le
                      {:main 0xd9b4bef9
                       :namecoin 0xfeb4bef9
                       :testnet 0xdab5bffa
                       :testnet3 0x0709110b}))


(defcodec command (compile-frame
                   (string :ascii :length 12)
                   (fn [s]
                     (->> 0 char
                          repeat
                          (concat s)
                          (take 12)
                          (apply str)))
                   (fn [s]
                     (->> s
                          (take-while (fn [s] (not= s (char 0))))
                          (apply str)))))

(defn sha-256 [bytes]
  (.digest (java.security.MessageDigest/getInstance "SHA-256") bytes))

(defn gen-checksum [n bytes]
  (take n (sha-256 (sha-256 bytes))))

(defcodec checksum
  (compile-frame [:ubyte :ubyte :ubyte :ubyte]))

(defcodec relay (enum :byte {true 1
                             false 0}))

(defcodec version-payload (compile-frame (ordered-map
                                          :version :int32-le
                                          :services :uint64-le
                                          :timestamp :int64-le
                                          :addr-recv net-addr
                                          :addr-from net-addr
                                          :nonce :uint64-le
                                          :user-agent varstr
                                          :start-height :int32-le
                                          :relay relay)))

(defcodec verack-payload nil-frame)

(defcodec addr-payload (compile-frame
                        (ordered-map :addrs
                                     (repeated net-addrt :prefix varint))))

(defcodec getaddr-payload nil-frame)

(defcodec ping-payload (ordered-map :payload :uint64-le))

(defcodec pong-payload (ordered-map :payload :uint64-le))

(def reject-keyword->value {:malformed 0x01
                            :invalid 0x10
                            :obsolete 0x11
                            :duplicate 0x12
                            :nonstandard 0x40
                            :dust 0x41
                            :insufficient-fee 0x42
                            :checkpoint 0x43})

(def reject-keyword->str {:malformed "REJECT_MALFORMED"
                          :invalid "REJECT_INVALID"
                          :obsolete "REJECT_OBSOLETE"
                          :duplicate "REJECT_DUPLICATE"
                          :nonstandard "REJECT_NONSTANDARD"
                          :dust "REJECT_DUST"
                          :insufficient-fee "REJECT_INSUFFICIENTFEE"
                          :checkpoint "REJECT_CHECKPOINT"})


(defcodec reject-payload (compile-frame (ordered-map :message varstr
                                                     :code :byte
                                                     :reason varstr)))


(defn reject-map [k message]
  (when-let [code (k reject-keyword->value)]
    {:message message
     :code    (k reject-keyword->value)
     :reason  (k reject-keyword->str)}))

(defcodec inv-vector (compile-frame (ordered-map :type (enum :uint32-le
                                                             {:error 0
                                                              :msg-tx 1
                                                              :msg-block 2})
                                                 :hash (repeat 32 :byte))
                                    (fn [{:keys [type bytes]}]
                                      {:type type
                                       :hash (gen-checksum 32 bytes)})
                                    identity))


(defcodec block-header (compile-frame (ordered-map :version :uint32-le
                                                   :prev-block (repeat 32 :byte)
                                                   :merkle-root (repeat 32 :byte)
                                                   :timestamp :uint32-le
                                                   :bits :uint32-le
                                                   :nonce :uint32-le
                                                   :txn-count varint)))


(defcodec inv-payload (compile-frame
                       (ordered-map
                        :inv-vectors (repeated inv-vector
                                               :prefix varint))))


(def command->payload {"version" version-payload
                       "verack" verack-payload
                       "addr"  addr-payload
                       "getaddr" getaddr-payload
                       "inv" inv-payload
                       "getdata" inv-payload
                       "ping" ping-payload
                       "pong" pong-payload
                       "reject" reject-payload})

(let [empty-byte-array (-> [] to-byte-buffer .array)]
  (defcodec bitcoin-network-message
    (e/header (ordered-map :magic magic
                           :command command
                           :length varint
                           :checksum checksum)
              (fn [{:keys [command]}]
                (-> command name command->payload))
              (fn [{:keys [command magic] :as b}]
                ;; TODO: Revisit with a header function that passes the
                ;; raw bytes to body->header. "encoding" should disappear.
                ;;
                ;; Also, this is really annoying. The version isn't in the
                ;; header. How do we handle multiple versions of the
                ;; bitcoin networking protocol?

                ;; -- johnwalker

                (let [first-encoding (-> command
                                         name
                                         command->payload
                                         (encode b))

                      ;; Keeps the empty payload case from exploding.
                      second-encoding (if first-encoding
                                        (-> first-encoding contiguous .array)
                                        empty-byte-array)]
                  {:magic magic
                   :command (name command)
                   :length (count second-encoding)
                   :checksum (gen-checksum 4 second-encoding)})))))





(defn write-message
  "Write a bitcoin network message"
  [m]
  ;; TODO - asserts
  (encode bitcoin-network-message m))


(defn read-message
  "Read a bitcoin network message"
  [x]
  (decode bitcoin-network-message x))
