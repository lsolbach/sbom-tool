(ns sbom-tool.util.functions
  "General, stateless helpers shared across layers. It depends on no other project
   namespace."
  (:require [clojure.edn :as edn])
  (:import [java.net URLEncoder]
           [java.util.concurrent Callable Executors Future]))

(defn bounded-pmap
  "Applies `f` to each of `coll` with at most `n` concurrent threads (a
   fixed-size thread pool), returning the results in input order. Bounds
   the concurrency of many individual HTTP round trips without
   serializing them."
  [n f coll]
  (let [pool (Executors/newFixedThreadPool n)]
    (try
      (->> coll
           (mapv (fn [x] (.submit pool ^Callable (fn [] (f x)))))
           (mapv (fn [^Future fut] (.get fut))))
      (finally (.shutdown pool)))))

(defn warn
  "Prints `Warning: <msg>` on `*err*`, keeping stdout clean for reports."
  [msg]
  (binding [*out* *err*]
    (println (str "Warning: " msg))))

(defn url-encode
  [s]
  (URLEncoder/encode s "UTF-8"))

(defn read-api-key-file
  "Reads the `:api-key` of the EDN file at `path`. Throws an ex-info
   whose `:sbom-tool/error-type` is the given `:not-found-error-type`
   when the file does not exist and `:malformed-error-type` when it is
   not valid EDN, so each caller keeps its own error types."
  [path {:keys [not-found-error-type malformed-error-type]}]
  (try
    (:api-key (edn/read-string (slurp path)))
    (catch java.io.FileNotFoundException e
      (throw (ex-info (str "file not found: " path)
                       {:sbom-tool/error-type not-found-error-type :path path}
                       e)))
    (catch RuntimeException e
      (throw (ex-info (str "malformed EDN: " (ex-message e))
                       {:sbom-tool/error-type malformed-error-type :path path}
                       e)))))
