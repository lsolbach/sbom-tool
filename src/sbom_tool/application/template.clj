(ns sbom-tool.application.template
  "Generate artifacts via templates."
  )

(defmulti render
  "Renders `report-key`'s `data` (as returned by a function from
   `sbom-tool.application.report`) in the given output `format` (e.g.
   `:edn`, `:markdown`).

   This is the extension point for output formats: an adapter registers a
   format by implementing a `defmethod` for it. `report-key` is the keyword
   naming the report (e.g. `:licenses`, `:vulnerabilities`, `:all`), which
   format-specific adapters may use to render each report appropriately."
  (fn [format _report-key _data] format))

(defmethod render :default
  [_format _report-key data]
  (pr-str data))
