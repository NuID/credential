(ns nuid.credential.challenge
  (:require
   [clojure.string :as string]
   [nuid.base64 :as base64]
   [nuid.codec :as codec]
   [nuid.credential.lib :as lib]
   [nuid.spec.lib :as spec.lib]
   [nuid.zk :as zk]
   [nuid.zk.knizk :as knizk]
   [nuid.zk.protocol :as zk.protocol]
   #?@(:clj  [[clojure.alpha.spec :as s]]
       :cljs [[clojure.spec.alpha :as s]])))

(s/def ::jwt ::spec.lib/not-empty-string)

(defn ->identifier
  [challenge]
  (val (first (select-keys challenge lib/identifiers))))

(defn -proof-dispatch
  [_ challenge]
  (->identifier challenge))

(defmulti  ->proof -proof-dispatch)
(defmethod ->proof ::zk.protocol/knizk
  [secret challenge]
  (->>
   (assoc challenge ::knizk/secret secret)
   (s/conform ::zk/provable)
   (zk/proof)
   (s/unform ::knizk/proof)))

  ;; TODO: Cross-platform ->jwt

(defn <-jwt
  [jwt]
  (->>
   (second (string/split jwt #"\."))
   (base64/str)
   (codec/decode "application/json")
   (lib/keywordize)))
