(ns sbom-tool.adapter.http
  "HTTP and JSON infrastructure shared by the live vulnerability adapters.

   Every request has a connect timeout, a request timeout and a response
   size cap, redirects are never followed, and a request is only sent to
   an https URL on the host of the service it belongs to (see
   `check-origin!`), so an API key never leaves for another host. A
   timeout, an oversize response, a non-2xx status and malformed JSON all
   surface as an ex-info carrying the caller's `:error-type`, which the
   adapters turn into a warning rather than aborting the run.

   A `service` is a map of `:base-url` (the https origin the requests are
   pinned to), `:error-type` (the `:sbom-tool/error-type` of a failed
   request) and `:service` (its name in messages)."
  (:require [cheshire.core :as json]
            [clojure.string :as string])
  (:import [java.net URI]
           [java.net.http HttpClient HttpClient$Redirect HttpRequest HttpRequest$BodyPublishers HttpResponse$BodyHandlers]
           [java.time Duration]))

(def ^:private json-processing-exception-class
  "Resolved via `Class/forName` rather than referenced as a `catch` class
   literal, so this namespace also loads under babashka: its SCI
   interpreter cannot resolve `com.fasterxml.jackson.core.
   JsonProcessingException` as a catch clause at analysis time, even
   though the class itself is present at runtime (babashka's `cheshire`
   is backed by real Jackson)."
  (Class/forName "com.fasterxml.jackson.core.JsonProcessingException"))

(def connect-timeout (Duration/ofSeconds 10))

(def ^:dynamic *request-timeout*
  "Time limit for a whole request, from sending it to the response headers."
  (Duration/ofSeconds 30))

(def ^:dynamic *max-response-bytes*
  "Largest response body accepted, in bytes (20 MiB)."
  (* 20 1024 1024))

(def ^:private http-client
  (delay (-> (HttpClient/newBuilder)
             (.connectTimeout connect-timeout)
             (.followRedirects HttpClient$Redirect/NEVER)
             (.build))))

(defn- request-failed
  "Builds the ex-info for a failed request to `url`; `detail` completes
   the message (e.g. \": malformed JSON: ...\")."
  [{:keys [error-type service]} url detail data cause]
  (ex-info (str service " request to " url " failed" detail)
           (merge {:sbom-tool/error-type error-type :url url} data)
           cause))

(defn- port-of
  [^URI uri]
  (let [port (.getPort uri)]
    (if (neg? port) 443 port)))

(defn check-origin!
  "Throws the service's request-failed ex-info unless `url` is an https
   URL with the host and port of the service's `:base-url`. Called
   before anything is sent, so request headers (API keys) never reach
   another host."
  [{:keys [base-url] :as service} url]
  (let [uri (try (URI/create url) (catch IllegalArgumentException _ nil))
        base (URI/create base-url)
        same-origin? (and uri
                          (= "https" (some-> (.getScheme uri) string/lower-case))
                          (some-> (.getHost uri) (.equalsIgnoreCase (.getHost base)))
                          (= (port-of uri) (port-of base)))]
    (when-not same-origin?
      (throw (request-failed service url
                             (str ": not an https URL on " (.getHost base))
                             {} nil)))))

(defn- header-map
  "Response headers as a map of lower-cased name to first value."
  [response]
  (into {}
        (map (fn [[k vs]] [(string/lower-case k) (first vs)]))
        (.map (.headers response))))

(defn- content-length
  [headers]
  (try (some-> (get headers "content-length") parse-long)
       (catch NumberFormatException _ nil)))

(defn- build-request
  [{:keys [method url headers body]}]
  (let [builder (reduce (fn [b [k v]] (.header b k v))
                        (-> (HttpRequest/newBuilder (URI/create url))
                            (.timeout *request-timeout*))
                        headers)]
    (case method
      :get (-> builder (.GET) (.build))
      :post (-> builder
                (.header "Content-Type" "application/json")
                (.POST (HttpRequest$BodyPublishers/ofString (json/generate-string body)))
                (.build)))))

(defn- read-limited
  "Reads at most `*max-response-bytes*` from `in`, or throws the
   service's request-failed ex-info when the body is larger."
  [service url headers in]
  (let [limit *max-response-bytes*
        too-large #(request-failed service url (str ": response is larger than " limit " bytes") {} nil)]
    (when (some-> (content-length headers) (> limit))
      (throw (too-large)))
    (let [bytes (.readNBytes in (int (inc limit)))]
      (when (> (alength bytes) limit)
        (throw (too-large)))
      bytes)))

(defn execute-json
  "Sends `request` (`:method` `:get` or `:post`, `:url`, `:headers`, and
   for `:post` a `:body` that is serialized as JSON) and returns
   `{:status n :headers {lower-case-name value} :body <parsed JSON,
   keyword keys>}`. Does not check the URL's origin; adapters call
   `request-json`, which does."
  [service {:keys [url] :as request}]
  (try
    (let [response (.send ^HttpClient @http-client (build-request request)
                          (HttpResponse$BodyHandlers/ofInputStream))
          status (.statusCode response)
          headers (header-map response)]
      (with-open [in (.body response)]
        (when-not (<= 200 status 299)
          (throw (request-failed service url (str " with HTTP " status) {:status status} nil)))
        {:status status
         :headers headers
         :body (json/parse-string (String. ^bytes (read-limited service url headers in) "UTF-8") true)}))
    (catch clojure.lang.ExceptionInfo e
      (throw e))
    (catch Exception e
      (throw (request-failed service url
                             (str ": " (if (instance? json-processing-exception-class e)
                                         (str "malformed JSON: " (ex-message e))
                                         (or (ex-message e) (.getName (class e)))))
                             {} e)))))

(defn request-json
  "Like `execute-json`, but first checks that `(:url request)` is an
   https URL on the service's host (see `check-origin!`)."
  [service {:keys [url] :as request}]
  (check-origin! service url)
  (execute-json service request))

(defn get-json
  "GETs `url` with `headers` and returns the parsed JSON body."
  [service url headers]
  (:body (request-json service {:method :get :url url :headers headers})))

(defn post-json
  "POSTs `body` as JSON to `url` with `headers` and returns the parsed
   JSON body."
  [service url headers body]
  (:body (request-json service {:method :post :url url :headers headers :body body})))
