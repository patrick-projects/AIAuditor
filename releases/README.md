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

Load in Burp: **Extensions → Add → Java →** select the JAR.
