(ns bitcoin-protocol.t-messages
  (:use midje.sweet)
  (:require [bitcoin-protocol.messages :as pm]))

(fact
 [1 3 5 8] => #(some even? %)) 
