(ns nuid.credential.challenge
  (:require
   [clojure.string :as string]
   [nuid.base64 :as base64]
   [nuid.codec :as codec]
   [nuid.credential.lib :as lib]
   [nuid.spec :as spec]
   [nuid.zk :as zk]
   [nuid.zk.knizk :as knizk]
   [nuid.zk.lib :as zk.lib]
   [nuid.zk.protocol :as zk.protocol]
   #?@(:clj  [[clojure.alpha.spec :as s]]
       :cljs [[clojure.spec.alpha :as s]])))

(s/def ::jwt spec/not-empty-string?)

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

(defn -verified-dispatch
  [_ x]
  (if (map? x)
    (->identifier x)
    x))

(defmulti  ->verified -verified-dispatch)
(defmethod ->verified ::zk.protocol/knizk
  [secret x]
  (let [challenge
        (if (keyword? x)
          (let [ch (zk.lib/default-challenge)]
            (->>
             (assoc ch ::knizk/secret secret)
             (zk/pub)
             (into ch)))
          x)]
    (->>
     (->proof secret challenge)
     (into challenge)
     (s/unform ::zk/challenge))))

  ;; TODO: Cross-platform ->jwt

(defn <-jwt
  [jwt]
  (->>
   (second (string/split jwt #"\."))
   (base64/str)
   (codec/decode "application/json")
   (lib/keywordize)))
