(ns io.johnwalker.bitcoin-protocol.gloss.extension.codecs
  (:use [gloss.data bytes string primitives]
        [gloss.core protocols structure formats])
  (:require [gloss.core :refer [ordered-map]]))

(defn header
  "It's the same as the gloss.core.codecs/header, but in read-codec
  the header and body are merged."
  [codec header->body body->header]
  (let [read-codec (compose-callback
                    codec
                    (fn [v b]
                      (let [body (header->body v)
                            [success m x] (read-bytes body b)]
                        [success (merge m v) x])))]
    (reify
      Reader
      (read-bytes [_ buf-seq]
        (read-bytes read-codec buf-seq))
      Writer
      (sizeof [_]
        nil)
      (write-bytes [_ buf val]
        (let [header (body->header val)
              body (header->body header)]
          (if (and (sizeof codec) (sizeof body))
            (with-buffer [buf (+ (sizeof codec) (sizeof body))]
              (write-bytes codec buf header)
              (write-bytes body buf val))
            (concat
             (write-bytes codec buf header)
             (write-bytes body buf val))))))))
