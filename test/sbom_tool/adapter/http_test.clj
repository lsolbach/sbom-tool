(ns sbom-tool.adapter.http-test
  (:require [clojure.string :as string]
            [clojure.test :refer [deftest is testing]]
            [sbom-tool.adapter.http :as http])
  (:import [java.io BufferedReader InputStreamReader OutputStream]
           [java.net InetAddress ServerSocket]
           [java.time Duration]))

(def ^:private service
  {:base-url "https://api.example.test/v1" :error-type :test-request-failed :service "Test"})

(defn- response
  "A raw HTTP/1.1 response whose body is delimited by `Content-Length`."
  [status body]
  (str "HTTP/1.1 " status "\r\nContent-Length: " (count (.getBytes ^String body "UTF-8"))
       "\r\nConnection: close\r\n\r\n" body))

(defn- write!
  [^OutputStream out ^String s]
  (.write out (.getBytes s "UTF-8"))
  (.flush out))

(defn- serve
  "Runs `f` with the URL of a one-shot loopback server. The server reads
   the request headers, then calls `respond` with the socket's output
   stream. Plain http is fine here: `execute-json` does not check origins."
  [respond f]
  (with-open [server (ServerSocket. 0 1 (InetAddress/getLoopbackAddress))]
    (let [handler (future
                    (try
                      (with-open [socket (.accept server)]
                        (let [reader (BufferedReader. (InputStreamReader. (.getInputStream socket)))]
                          (loop [line (.readLine reader)]
                            (when-not (or (nil? line) (string/blank? line))
                              (recur (.readLine reader)))))
                        (respond (.getOutputStream socket)))
                      (catch Exception _ nil)))]
      (try
        (f (str "http://127.0.0.1:" (.getLocalPort server) "/vulns"))
        (finally (future-cancel handler))))))

(defn- failure
  [url]
  (try (http/execute-json service {:method :get :url url :headers {}})
       nil
       (catch clojure.lang.ExceptionInfo e e)))

(deftest execute-json-test
  (testing "returns status, lower-cased headers and the parsed body of a 2xx response"
    (serve #(write! % (response "200 OK" "{\"id\": \"CVE-1\"}"))
           (fn [url]
             (let [result (http/execute-json service {:method :get :url url :headers {}})]
               (is (= 200 (:status result)))
               (is (= {:id "CVE-1"} (:body result)))
               (is (= "close" (get (:headers result) "connection")))))))
  (testing "a non-2xx response fails with the caller's error type, url and status"
    (serve #(write! % (response "503 Service Unavailable" "{}"))
           (fn [url]
             (let [e (failure url)]
               (is (= :test-request-failed (:sbom-tool/error-type (ex-data e))))
               (is (= 503 (:status (ex-data e))))
               (is (= url (:url (ex-data e))))
               (is (= (str "Test request to " url " failed with HTTP 503") (ex-message e)))))))
  (testing "malformed JSON fails"
    (serve #(write! % (response "200 OK" "{not json"))
           (fn [url]
             (let [e (failure url)]
               (is (= :test-request-failed (:sbom-tool/error-type (ex-data e))))
               (is (string/starts-with? (ex-message e) (str "Test request to " url " failed: malformed JSON: ")))))))
  (testing "a connection that cannot be made fails"
    (let [e (failure "http://127.0.0.1:1/vulns")]
      (is (= :test-request-failed (:sbom-tool/error-type (ex-data e))))))
  (testing "a redirect is a failure and is not followed"
    (serve #(write! % "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/elsewhere\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
           (fn [url]
             (is (= 302 (:status (ex-data (failure url)))))))))

(deftest execute-json-post-test
  (testing "a posted body arrives as JSON with a JSON content type"
    (let [received (promise)]
      (with-open [server (ServerSocket. 0 1 (InetAddress/getLoopbackAddress))]
        (let [handler (future
                        (with-open [socket (.accept server)]
                          (let [reader (BufferedReader. (InputStreamReader. (.getInputStream socket)))
                                lines (doall (take-while #(not (string/blank? %)) (repeatedly #(.readLine reader))))
                                length (some #(second (re-find #"(?i)^content-length:\s*(\d+)" %)) lines)
                                chars (char-array (parse-long length))]
                            (.read reader chars 0 (alength chars))
                            (deliver received {:headers lines :body (String. chars)}))
                          (write! (.getOutputStream socket) (response "200 OK" "{\"ok\": true}"))))
              url (str "http://127.0.0.1:" (.getLocalPort server) "/querybatch")
              result (http/execute-json service {:method :post :url url :headers {"X-Key" "k"} :body {:queries []}})
              {:keys [headers body]} (deref received 2000 nil)]
          (is (= {:ok true} (:body result)))
          (is (= "{\"queries\":[]}" body))
          (is (some #(re-find #"(?i)^content-type:\s*application/json" %) headers))
          (is (some #(re-find #"(?i)^x-key:\s*k" %) headers))
          (future-cancel handler))))))

(deftest execute-json-limits-test
  (testing "a request that gets no answer within the request timeout fails"
    (serve (fn [_] (Thread/sleep 3000))
           (fn [url]
             (let [start (System/nanoTime)
                   e (binding [http/*request-timeout* (Duration/ofMillis 300)] (failure url))
                   elapsed-ms (/ (- (System/nanoTime) start) 1e6)]
               (is (= :test-request-failed (:sbom-tool/error-type (ex-data e))))
               (is (< elapsed-ms 2500))))))
  (testing "a body larger than the limit, announced by Content-Length, fails"
    (serve #(write! % (response "200 OK" (apply str (repeat 50 "x"))))
           (fn [url]
             (let [e (binding [http/*max-response-bytes* 10] (failure url))]
               (is (= :test-request-failed (:sbom-tool/error-type (ex-data e))))
               (is (string/includes? (ex-message e) "larger than 10 bytes"))))))
  (testing "a body larger than the limit without a Content-Length fails"
    (serve #(write! % (str "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n\"" (apply str (repeat 50 "x")) "\""))
           (fn [url]
             (let [e (binding [http/*max-response-bytes* 10] (failure url))]
               (is (string/includes? (ex-message e) "larger than 10 bytes"))))))
  (testing "a body within the limit is accepted"
    (serve #(write! % (response "200 OK" "\"ok\""))
           (fn [url]
             (is (= "ok" (:body (binding [http/*max-response-bytes* 10]
                                  (http/execute-json service {:method :get :url url :headers {}})))))))))

(deftest check-origin-test
  (testing "accepts https URLs on the service's host, whatever the path, query or case"
    (is (nil? (http/check-origin! service "https://api.example.test/v1/vulns/1")))
    (is (nil? (http/check-origin! service "https://API.example.test/other?page=2")))
    (is (nil? (http/check-origin! service "https://api.example.test:443/v1"))))
  (testing "rejects every other scheme, host and port"
    (doseq [url ["http://api.example.test/v1"
                 "https://evil.example/v1"
                 "https://api.example.test.evil.example/v1"
                 "https://api.example.test@evil.example/v1"
                 "https://api.example.test:8443/v1"
                 "ftp://api.example.test/v1"
                 "/v1/relative"
                 "https://api.example.test/with space"]]
      (let [e (try (http/check-origin! service url) nil
                   (catch clojure.lang.ExceptionInfo e e))]
        (is (some? e) url)
        (is (= :test-request-failed (:sbom-tool/error-type (ex-data e))) url)
        (is (= url (:url (ex-data e))) url)))))

(deftest request-json-test
  (testing "refuses a URL on another host before sending anything"
    (serve (fn [_] (throw (ex-info "the server must not be contacted" {})))
           (fn [url]
             (let [e (try (http/request-json service {:method :get :url url :headers {"Authorization" "Bearer secret"}})
                          (catch clojure.lang.ExceptionInfo e e))]
               (is (string/includes? (ex-message e) "not an https URL on api.example.test"))
               (is (nil? (:status (ex-data e)))))))))
