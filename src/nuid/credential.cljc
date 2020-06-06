(ns nuid.credential
  (:require
   [nuid.base64 :as base64]
   [nuid.credential.datalog :as datalog]
   [nuid.credential.lib :as lib]
   [nuid.cryptography.base64 :as crypt.base64]
   [nuid.cryptography.hash :as hash]
   [nuid.cryptography.hash.algorithm :as hash.alg]
   [nuid.cryptography.hash.algorithm.scrypt :as scrypt]
   [nuid.elliptic.curve :as curve]
   [nuid.elliptic.curve.point :as point]
   [nuid.spec :as spec]
   [nuid.zk :as zk]
   [nuid.zk.knizk :as knizk]
   [nuid.zk.protocol :as zk.protocol]
   #?@(:clj  [[clojure.alpha.spec :as s]]
       :cljs [[clojure.spec.alpha :as s]])))

(s/def ::credential
  (s/or
   ::zk/credential    ::zk/credential
   ::knizk/credential ::knizk/credential))

(defn ->tag
  [x]
  (let [c (s/conform ::credential x)]
    (if (s/invalid? c)
      c
      (first c))))

(defmulti  <- ->tag)
(defmethod <- ::zk/credential
  [x]
  (into {} (vals (dissoc (zk/credential x) ::zk/protocol))))

(defmethod <- ::knizk/credential
  [x]
  (into {} (vals (knizk/credential x))))

(s/def :nuid/credential
  (s/keys
   :req
   [::curve/parameters
    ::curve/point]
   :opt
   [::crypt.base64/salt
    ::hash/algorithm
    ::scrypt/N
    ::scrypt/r
    ::scrypt/p
    ::scrypt/length
    :string.normalization/form]))

(def ->nuid
  (comp
   base64/encode
   lib/->cbor
   datalog/->lookup-ref))

(s/def ::challenge
  (s/or
   ::zk/challenge    ::zk/challenge
   ::knizk/challenge ::knizk/challenge))

(defmulti  ->challenge (fn [t _] t))
(defmethod ->challenge ::zk.protocol/knizk
  [_ credential]
  (into
   (knizk/default-challenge-parameters)
   {::zk/protocol ::zk.protocol/knizk
    ::knizk/pub   (spec/select-keys ::point/parameters credential)
    ::knizk/keyfn (->>
                   (hash.alg/parameters-multi-spec credential)
                   (spec/keys-spec->keys)
                   (into [::hash/algorithm])
                   (select-keys credential))}))

(s/def ::proof
  (s/or
   ::zk/proof    ::zk/proof
   ::knizk/proof ::knizk/proof))

(s/def ::verified
  (s/or
   ::zk/verified    ::zk/verified
   ::knizk/verified ::knizk/verified))
