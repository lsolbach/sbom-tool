(defproject sbom-tool "0.1.0"
  :description "Reads SBOMs and reports license information"
  :dependencies [[org.clojure/clojure "1.12.5"]
                 [org.clojure/data.csv "1.1.1"]
                 [cheshire/cheshire "6.2.0"]
                 [org.clojure/tools.cli "1.4.256"]
                 [babashka/fs "0.5.34"]]
  :repl-options {:init-ns sbom-tool.adapter.ui.cli}
  :uberjar-name "sbom-tool.jar"
  :main sbom-tool.adapter.ui.cli)
