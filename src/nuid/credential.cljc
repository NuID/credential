(ns nuid.credential
  (:require
   [nuid.zk :as zk]))

(defprotocol Store
  (transact [client opts])
  (query    [client opts]))

(defprotocol Credentialable
  (parse  [x] [x opts])
  (coerce [x] [x opts])
  (from   [x] [x opts]))

(defprotocol Credential
  (proof  [c opts])
  (verify [c opts]))

(def dispatch (comp :id :protocol))
(defmulti coerce* dispatch)
(defmethod coerce* "knizk"
  [c]
  (zk/coerce c))

(defmulti proof* dispatch)
(defmethod proof* "knizk"
  [c]
  (zk/proof c))

(defmulti verify* dispatch)
(defmethod verify* "knizk"
  [c]
  (zk/verified? c))
