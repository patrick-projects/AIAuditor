# Pre-built extension JAR

**File:** `ai-auditor-jar-with-dependencies.jar` (not always present in git; build locally or grab CI output).

**Local build and copy into this folder:**

```bash
./scripts/build-release-jar.sh
```

**Manual:**

```bash
mvn clean package -DskipTests
cp target/ai-auditor-*-jar-with-dependencies.jar releases/ai-auditor-jar-with-dependencies.jar
```

**CI:** Every push to `main` runs **Build extension JAR** in the repo’s Actions tab and uploads the fat JAR as artifact **ai-auditor-burp-jar**.

Load in Burp: **Extensions → Add → Java →** select the JAR.
