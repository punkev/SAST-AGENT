# SAST Master Ignore Patterns & File Exclusion Rules

**CRITICAL MANDATE FOR ALL AGENTS**:
Before reading any files or traversing the attached source directory, you **MUST** apply the exclusion rules specified here and in `.sast-agent/config/ignore-paths.yml`. Under no circumstances should non-code assets, media files, fonts, binaries, test files, or build artifacts be read into context.

---

## 1. Universal Media, Documents, Fonts & Binaries (DO NOT READ)

### Images & Graphics
`*.png`, `*.jpg`, `*.jpeg`, `*.gif`, `*.svg`, `*.ico`, `*.webp`, `*.bmp`, `*.tiff`, `*.tif`, `*.psd`, `*.ai`, `*.eps`, `*.raw`, `*.cr2`, `*.heic`, `*.heif`, `*.avif`

### Audio & Video
`*.mp4`, `*.webm`, `*.mkv`, `*.avi`, `*.mov`, `*.flv`, `*.wmv`, `*.m4v`, `*.3gp`, `*.mp3`, `*.wav`, `*.ogg`, `*.flac`, `*.aac`, `*.m4a`, `*.wma`, `*.aiff`

### Documents & Spreadsheets
`*.pdf`, `*.doc`, `*.docx`, `*.xls`, `*.xlsx`, `*.ppt`, `*.pptx`, `*.odt`, `*.ods`, `*.odp`, `*.rtf`, `*.pages`, `*.numbers`, `*.key`

### Fonts
`*.ttf`, `*.otf`, `*.woff`, `*.woff2`, `*.eot`, `*.fon`

### Compiled Binaries, Archives & Intermediate Objects
`*.jar`, `*.war`, `*.ear`, `*.class`, `*.exe`, `*.dll`, `*.so`, `*.dylib`, `*.bin`, `*.dat`, `*.pyc`, `*.pyo`, `*.zip`, `*.tar`, `*.gz`, `*.tgz`, `*.7z`, `*.rar`, `*.bz2`, `*.xz`, `*.iso`, `*.dmg`, `*.pdb`, `*.obj`, `*.node`

---

## 2. Test Suites, Mocks & Test Fixtures (DO NOT READ / EXCLUDE FROM SAST)

Test code contains synthetic vulnerabilities and mock credentials that create high false-positive rates and waste token context.

### Java Test Paths & Patterns
- `**/src/test/**`
- `**/src/it/**`
- `**/*Test.java`, `**/*Tests.java`, `**/*TestCase.java`, `**/Test*.java`, `**/IT*.java`, `**/*IT.java`
- `**/mock/**`, `**/mocks/**`
- `**/testdata/**`, `**/fixtures/**`, `**/sample/**`, `**/samples/**`, `**/demo/**`

### Node.js / TypeScript Test Paths & Patterns
- `**/test/**`, `**/tests/**`, `**/tst/**`, `**/__tests__/**`, `**/__mocks__/**`
- `**/*.test.js`, `**/*.test.jsx`, `**/*.test.ts`, `**/*.test.tsx`, `**/*.test.mjs`, `**/*.test.cjs`
- `**/*.spec.js`, `**/*.spec.jsx`, `**/*.spec.ts`, `**/*.spec.tsx`, `**/*.spec.mjs`, `**/*.spec.cjs`
- `**/cypress/**`, `**/playwright/**`, `**/e2e/**`
- `**/*.mock.js`, `**/*.mock.ts`

---

## 3. Build Outputs, Dependency Trees & Generated Caches

### Java / JVM Build Directories
- `**/target/`
- `**/build/`
- `**/bin/`
- `**/out/`
- `**/.gradle/`
- `**/.mvn/`
- `**/.settings/`
- `**/.classpath`, `**/.project`, `**/*.iml`, `**/.factorypath`

### Node.js / JavaScript Build Directories & Bundles
- `**/node_modules/`
- `**/dist/`
- `**/.next/`, `**/.nuxt/`, `**/.output/`, `**/.turbo/`, `**/.cache/`
- `**/coverage/`, `**/.nyc_output/`
- `*.min.js`, `*.min.css`, `*.map`, `*.bundle.js`
- `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `bun.lockb`

---

## 4. Version Control & System Metadata
- `**/.git/**`, `**/.svn/**`, `**/.hg/**`
- `**/.idea/**`, `**/.vscode/**`
- `**/.DS_Store`, `**/Thumbs.db`, `**/logs/**`
- `**/.sast-agent/**` (internal scanner state)

---

## 5. Security Exceptions (DO NOT IGNORE)

The following configuration files contain crucial security controls and **must always be analyzed**:
- **Java**: `application*.yml`, `application*.properties`, `bootstrap*.yml`, `pom.xml`, `build.gradle`, `build.gradle.kts`, `web.xml`, `SecurityConfig.java`, `WebSecurityConfig*.java`.
- **Node.js**: `package.json`, `.env*`, `tsconfig.json`, `server.ts/js`, `app.ts/js`, middleware configuration files.
