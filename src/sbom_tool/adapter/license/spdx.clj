(ns sbom-tool.adapter.license.spdx
  "Adapter for SPDX license information."
  (:require [clojure.string :as str]
            [clojure.set :as set]
            [sbom-tool.domain.license :as license]))

;; TODO implement reader for SPDX license information