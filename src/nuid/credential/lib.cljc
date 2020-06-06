(ns nuid.credential.lib
  (:require
   [nuid.codec :as codec]
   [nuid.zk :as zk]
   [nuid.zk.lib :as zk.lib]))

(def identifiers
  #{::zk/protocol})

(def ->cbor
  (partial
   codec/encode
   "application/cbor"))

(def <-cbor
  (partial
   codec/decode
   "application/cbor"))

(def stringify
  zk.lib/stringify)

(def keywordize
  zk.lib/keywordize)
