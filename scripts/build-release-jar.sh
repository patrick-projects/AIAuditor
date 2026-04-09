#!/usr/bin/env bash
# Builds the Burp extension and copies the fat JAR into releases/ for git commit.
set -euo pipefail
cd "$(dirname "$0")/.."
mvn -q clean package -DskipTests
JAR=$(ls target/*-jar-with-dependencies.jar | head -1)
OUT="releases/ai-auditor-jar-with-dependencies.jar"
cp -f "$JAR" "$OUT"
echo "Built: $OUT ($(wc -c < "$OUT") bytes)"
