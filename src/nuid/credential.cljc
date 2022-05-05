(ns nuid.credential
  (:require
   [clojure.spec.alpha :as s]
   [nuid.base64 :as base64]
   [nuid.codec :as codec]
   [nuid.cryptography.base64 :as crypt.base64]
   [nuid.cryptography.hash :as hash]
   [nuid.cryptography.hash.algorithm :as hash.alg]
   [nuid.cryptography.hash.algorithm.scrypt :as scrypt]
   [nuid.elliptic.curve :as curve]
   [nuid.elliptic.curve.point :as point]
   [nuid.spec.lib :as spec.lib]
   [nuid.zk :as zk]
   [nuid.zk.knizk :as knizk]
   [nuid.zk.lib :as zk.lib]
   [nuid.zk.protocol :as zk.protocol]))


   ;;;
   ;;; NOTE: predicates, specs
   ;;;


(def identifiers
  #{::zk/protocol})

(s/def ::credential
  (s/or
   ::zk/credential    ::zk/credential
   ::knizk/credential ::knizk/credential))

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

(s/def :nuid/credentials
  (s/coll-of :nuid/credential))

(s/def ::challenge
  (s/or
   ::zk/challenge    ::zk/challenge
   ::knizk/challenge ::knizk/challenge))

(s/def ::proof
  (s/or
   ::zk/proof ::zk/proof
   ::knizk/proof ::knizk/proof))

(s/def ::verified
  (s/or
   ::zk/verified ::zk/verified
   ::knizk/verified ::knizk/verified))


   ;;;
   ;;; NOTE: helper functions, internal logic
   ;;;


(defn credential-dispatch [x]
  (let [c (s/conform ::credential x)]
    (if (s/invalid? c)
      c
      (first c))))

(defn challenge-dispatch
  ([t] t)
  ([t _] t))


   ;;;
   ;;; NOTE: multimethods, hierarchies
   ;;;


(defmulti credential credential-dispatch)

;; NOTE: naming this `challenge` causes a conflict in `cljs` with the
;; `nuid.credential.challenge` namespace
(defmulti generate-challenge challenge-dispatch)


   ;;;
   ;;; NOTE: credential api
   ;;;


(def stringify
  zk.lib/stringify)

(def keywordize
  zk.lib/keywordize)

(defn lookup-ref [c]
  (when (contains? c ::curve/point)
    (find c ::curve/point)))

(def nuid
  (comp
   base64/encode
   (partial codec/encode "application/cbor")
   lookup-ref))

(def nuid->lookup-ref
  (comp
   (partial codec/decode "application/cbor")
   base64/decode))


   ;;;
   ;;; NOTE: multimethod implementations
   ;;;


(defmethod credential ::zk/credential
  [x]
  (->>
   (zk/credential x)
   (s/unform ::zk/credential)
   ((fn [x]
      (dissoc x ::zk/protocol)))
   (vals)
   (into {})))

(defmethod credential ::knizk/credential
  [x]
  (->>
   (knizk/credential x)
   (s/unform ::knizk/credential)
   (vals)
   (into {})))

(defmethod generate-challenge ::zk.protocol/knizk
  ([_]
   (into
    (knizk/default-challenge-parameters)
    {::zk/protocol ::zk.protocol/knizk}))
  ([_ c]
   (into
    (knizk/default-challenge-parameters)
    {::zk/protocol ::zk.protocol/knizk
     ::knizk/pub   (spec.lib/select-keys ::point/parameters c)
     ::knizk/keyfn (let [spec (hash.alg/parameters-multi-spec c)
                         ks   (conj (spec.lib/keys-spec->keys spec)
                                    ::hash/algorithm)]
                     (select-keys c ks))})))
