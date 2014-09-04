- [bitcoin-protocol](#bitcoin-protocol)
  - [Examples](#examples)
    - [Build a version message](#build-a-version-message)
    - [Read the version message back](#read-the-version-message-back)
    - [Verify the insides](#verify-the-insides)
    - [The Rest](#the-rest)
- [License](#license)

# bitcoin-protocol<a id="sec-1" name="sec-1"></a>



This is an implementation of the [Bitcoin networking protocol](https://en.bitcoin.it/wiki/Protocol_specification). It can
be used to communicate with peers within Bitcoin networks. The
library handles deterministic fields like checksums and lengths, but
the programmer must specify non-deterministic fields like nonces.

Documentation to come. Mostly untested goodness at the moment.

```clojure
;; Latest version on Clojars
[io.johnwalker/bitcoin-protocol "0.17.3"]
```

## Examples<a id="sec-1-1" name="sec-1-1"></a>

The two functions you care most about are `write-message` and
`read-message.` `write-message` will convert hashmaps to
Bytebuffers. `read-message` will bring Bytebuffers back to
hashmaps.

### Build a version message<a id="sec-1-1-1" name="sec-1-1-1"></a>

```clojure
(require '[bitcoin-protocol.messages :refer [write-message read-message]])

(def my-version-messages (write-message
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
                           :relay true}))

;; #<HeapByteBuffer java.nio.HeapByteBuffer[pos=0 lim=122 cap=122]>
```

### Read the version message back<a id="sec-1-1-2" name="sec-1-1-2"></a>

`Read-message` works for other messages, like getaddr, ping, pong
and so forth.

```clojure
(def read-it-back (read-message my-version-message))
```

```clojure
{:addr-from {:port 0 :ip "0.0.0.0" :services 1N}
 :user-agent "/Satoshi:0.7.2/"
 :command "version"
 :magic :main
 :start-height 212672
 :relay true
 :checksum [133 39 57 227]
 :length 101
 :version 60001
 :timestamp 1355854353
 :nonce 7284544412836900411N
 :services 1N
 :addr-recv {:port 0 :ip "0.0.0.0" :services 1N}
```

### Verify the insides<a id="sec-1-1-3" name="sec-1-1-3"></a>

Don't be shy when it comes to verifying the encoding. The raw bytes
are easy to see (and there are better formatters in Clojure land).

```clojure
(defn- str-bytes [h]
  (clojure.string/trimr
   (apply str
          (for [x (range (.remaining h))]
            (format "%02X " (.get h x))))))

(def raw-bytes (str-bytes my-version-message)
```

### The Rest<a id="sec-1-1-4" name="sec-1-1-4"></a>

Everything else works just like the version message. Some of them
haven't been tested yet, however. If you run into an error, please
report it to me. I'll be especially happy to accept `test.check` or
unit tests that demonstrate the failure.

Presently, `read-message` and `write-message` is expected to work
for

```
version
verack
addr
getaddr
inv
ping
pong
reject
```

while these are around, but are untested.

```
alert
block
getdata
notfound
getblocks
getheaders
tx
```

# License<a id="sec-2" name="sec-2"></a>

Copyright © 2014 John Walker

Distributed under the Eclipse Public License version 1.0.
