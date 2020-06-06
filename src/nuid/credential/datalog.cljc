(ns nuid.credential.datalog
  (:require
   [nuid.base64 :as base64]
   [nuid.credential.lib :as lib]
   [nuid.elliptic.curve :as curve]))

(defn ->lookup-ref
  [credential]
  (when (contains? credential ::curve/point)
    (first
     (select-keys credential [::curve/point]))))

(def nuid->lookup-ref
  (comp
   lib/<-cbor
   base64/decode))
