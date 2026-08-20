#!/usr/bin/env bb
(ns sbom-tool
  (:require [sbom-tool.adapter.ui.cli :as cli]))

(apply cli/-main *command-line-args*)
