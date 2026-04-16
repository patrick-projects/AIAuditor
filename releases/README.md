# Pre-built extension JAR (in this repo)

**File:** [`ai-auditor-jar-with-dependencies.jar`](./ai-auditor-jar-with-dependencies.jar) — committed so anyone can install without building.

**Direct download (raw):**  
`https://github.com/patrick-projects/AIAuditor/raw/main/releases/ai-auditor-jar-with-dependencies.jar`

**Refresh this file after code changes:**

```bash
./scripts/build-release-jar.sh
git add releases/ai-auditor-jar-with-dependencies.jar
```

**CI:** Pushes to `main` still upload a workflow artifact **ai-auditor-burp-jar** under Actions. Tagged releases also attach the same fat JAR on the Releases page.

Load in Burp: **Extender → Extensions → Add →** extension type **Java** → select the JAR → **Next**.

The JAR is built from this repo’s source and is subject to the **GNU Affero General Public License v3.0**; see the root [`LICENSE`](../LICENSE) file. If you pass the JAR to others, comply with the AGPL (including source-offer requirements as applicable).
