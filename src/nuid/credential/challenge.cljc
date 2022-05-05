(ns nuid.credential.challenge
  (:require
   [clojure.spec.alpha :as s]
   [clojure.string :as string]
   [nuid.base64 :as base64]
   [nuid.codec :as codec]
   [nuid.credential :as credential]
   [nuid.spec :as spec]
   [nuid.zk :as zk]
   [nuid.zk.knizk :as knizk]
   [nuid.zk.lib :as zk.lib]
   [nuid.zk.protocol :as zk.protocol]))


   ;;;
   ;;; NOTE: specs
   ;;;


(s/def ::jwt ::spec/not-empty-string)


   ;;;
   ;;; NOTE: helper functions, internal logic
   ;;;


(defn identifier [challenge]
  (val
   (first
    (select-keys challenge credential/identifiers))))

(defn proof-dispatch
  [_ challenge]
  (identifier challenge))

(defn verified-dispatch
  [_ x]
  (if (map? x) (identifier x) x))


    ;;;
    ;;; NOTE: multimethod, hierarchies
    ;;;


(defmulti proof proof-dispatch)
(defmulti verified verified-dispatch)


   ;;;
   ;;; NOTE: multimethod implementations
   ;;;


(defmethod proof ::zk.protocol/knizk
  [secret challenge]
  (->>
   (assoc challenge ::knizk/secret secret)
   (s/conform ::zk/provable)
   (zk/proof)
   (s/unform ::knizk/proof)))

(defmethod verified ::zk.protocol/knizk
  [secret x]
  (let [challenge (if (keyword? x)
                    (let [ch (zk.lib/default-challenge)]
                      (->> (assoc ch ::knizk/secret secret)
                           (zk/pub)
                           (into ch)))
                    x)]
    (->> (proof secret challenge)
         (into challenge)
         (s/unform ::zk/challenge))))


   ;;;
   ;;; NOTE: api
   ;;;


;; TODO: cross-platform, signed jwt handling
(defn jwt->challenge [jwt]
  (->>
   (string/split jwt #"\.")
   (second)
   (base64/str)
   (codec/decode "application/json")
   (zk.lib/keywordize)))
