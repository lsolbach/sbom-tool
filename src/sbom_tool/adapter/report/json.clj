(ns sbom-tool.adapter.report.json
  "Renders `sbom-tool.application.report` reports as JSON. Unlike markdown,
   JSON needs no per-report template: report data is already plain
   maps/vectors, so it is serialized generically regardless of `report-key`."
  (:require [cheshire.core :as json]
            [sbom-tool.application.template :as template]))

(defmethod template/render :json
  [_format _report-key data]
  (json/generate-string data {:pretty true}))
