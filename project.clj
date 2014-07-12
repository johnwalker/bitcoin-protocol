(defproject com.github.johnwalker/bitcoin-protocol "0.17.0-SNAPSHOT"
  :description "An implementation of the Bitcoin networking protocol."
  :url "https://github.com/johnwalker/bitcoin-protocol"
  :license {:name "Eclipse Public License"
            :url "http://www.eclipse.org/legal/epl-v10.html"}
  :dependencies [[org.clojure/clojure "1.6.0"]
                 [gloss "0.2.2"]]
  :profiles {:dev {:dependencies [[org.clojure/tools.namespace "0.2.4"]
                                  [org.clojure/test.check "0.5.8"]]}})
