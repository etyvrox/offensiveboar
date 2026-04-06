<p align="center">
  <h2 align="center">OffensiveBoar</h2>
  <p align="center">Find leaked credentials.</p>
</p>

---

# What is OffensiveBoar 🐽

**OffensiveBoar** is an enhanced fork of TruffleHog with additional features for comprehensive secret scanning. It is a powerful tool for **Discovery, Classification, Validation,** and **Analysis** of leaked credentials. In this context, secret refers to a credential a machine uses to authenticate itself to another machine. This includes API keys, database passwords, private encryption keys, tokens, and more.

## Key Features

### 🔍 Discovery
OffensiveBoar can look for secrets in many places including Git repositories, Jira issues, chats, wikis, logs, API testing platforms, object stores, filesystems and more.

### 📁 Classification
OffensiveBoar classifies over 800 secret types, mapping them back to the specific identity they belong to. Is it an AWS secret? Stripe secret? Cloudflare secret? Postgres password? SSL Private key? Sometimes it's hard to tell looking at it, so OffensiveBoar classifies everything it finds.

### ✅ Validation
For every secret OffensiveBoar can classify, it can also log in to confirm if that secret is live or not. This step is critical to know if there's an active present danger or not.

### 🔬 Analysis
For the 20 some of the most commonly leaked out credential types, instead of sending one request to check if the secret can log in, OffensiveBoar can send many requests to learn everything there is to know about the secret. Who created it? What resources can it access? What permissions does it have on those resources?

## 🆕 New Features in This Fork

### 🌍 Multi-Language Secret Detection
OffensiveBoar includes enhanced custom detectors that support searching for passwords and tokens in multiple languages:
- **English**: Detects variations like `password`, `Password`, `PASSWORD`, `token`, `Token`, etc.
- **Russian**: Detects Cyrillic variations like `пароль`, `Пароль`, etc.
- **And more**: Easily extensible to support additional languages via the `--custom-languages` flag

Example usage:
```bash
offensiveboar filesystem /path/to/scan --custom-languages en,ru
```

### 🎫 Jira Integration
OffensiveBoar can scan Jira issues for leaked credentials across all three deployment types:
- **Jira Cloud** — Basic Auth with email + API token, API v3
- **Jira Server/Data Center (PAT)** — Bearer token, API v2
- **Jira Server/Data Center (Basic Auth)** — username + password, API v2, no token creation needed
- Scans all projects with pagination, analyzes summaries, descriptions, and comments (plain text + ADF)
- Configurable request throttling to stay within API rate limits
- `--days N` to scope scans to recently updated issues and comments only

**Jira Cloud:**
```bash
offensiveboar jira --jira-url https://your-domain.atlassian.net \
  --jira-email your@email.com --jira-token YOUR_API_TOKEN \
  --jira-throttle 10rps --days 7
```

**Jira Server/DC — username + password (no token needed):**
```bash
offensiveboar jira --jira-url https://jira.corp.local \
  --jira-username admin --jira-password secret \
  --jira-throttle 5rps --days 2
```

**Jira Server/DC — Bearer token / PAT:**
```bash
offensiveboar jira --jira-url https://jira.corp.local \
  --jira-token YOUR_PAT --jira-throttle 5rps
```

### 🔐 Enhanced Token Detection
- Detects various token formats including:
  - Standard tokens: `token`, `tokens`, `Token`, `TOKEN`, etc.
  - Authorization headers: `Authorization: Bearer <token>` (minimum 16 characters)
  - Basic auth: `Authorization: Basic <base64>` (minimum 20 characters)

# :rocket: Quick Start

## 1: Scan a repo for only verified secrets

```bash
offensiveboar git https://github.com/your-org/your-repo --results=verified
```

## 2: Scan a GitHub Org for only verified secrets

```bash
offensiveboar github --org=your-org --results=verified
```

## 3: Scan Jira issues

**Jira Cloud:**
```bash
offensiveboar jira --jira-url https://your-domain.atlassian.net \
  --jira-email your@email.com --jira-token YOUR_API_TOKEN \
  --custom-languages en,ru
```

**Jira Server/DC — username + password:**
```bash
offensiveboar jira --jira-url https://jira.corp.local \
  --jira-username admin --jira-password secret \
  --custom-languages en,ru
```

**Jira Server/DC — Bearer token/PAT:**
```bash
offensiveboar jira --jira-url https://jira.corp.local \
  --jira-token YOUR_PAT --custom-languages en,ru
```

## 4: Scan filesystem with multi-language support

```bash
offensiveboar filesystem /path/to/scan --custom-languages en,ru,es
```

## 5: Scan individual files or directories

```bash
offensiveboar filesystem path/to/file1.txt path/to/file2.txt path/to/dir
```

## 6: Scan an S3 bucket for high-confidence results

```bash
offensiveboar s3 --bucket=<bucket name> --results=verified,unknown
```

# :floppy_disk: Installation

### Compile from source

```bash
git clone https://github.com/etyvrox/offensiveboar.git
cd offensiveboar
go install
```

### Using installation script

```bash
curl -sSfL https://raw.githubusercontent.com/etyvrox/offensiveboar/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

### Using installation script, verify checksum signature (requires cosign to be installed)

```bash
curl -sSfL https://raw.githubusercontent.com/etyvrox/offensiveboar/main/scripts/install.sh | sh -s -- -v -b /usr/local/bin
```

### Using installation script to install a specific version

```bash
curl -sSfL https://raw.githubusercontent.com/etyvrox/offensiveboar/main/scripts/install.sh | sh -s -- -b /usr/local/bin <ReleaseTag like v3.56.0>
```

# :memo: Usage

OffensiveBoar has a sub-command for each source of data that you may want to scan:

- `git` - Scan git repositories
- `github` - Scan GitHub repositories and organizations
- `gitlab` - Scan GitLab repositories
- `jira` - Scan Jira issues (NEW!)
- `docker` - Scan Docker images
- `s3` - Scan AWS S3 buckets
- `filesystem` - Scan files and directories (with multi-language support)
- `syslog` - Scan syslog streams
- `circleci` - Scan CircleCI builds
- `travisci` - Scan Travis CI builds
- `gcs` - Scan Google Cloud Storage buckets
- `postman` - Scan Postman workspaces
- `jenkins` - Scan Jenkins servers
- `elasticsearch` - Scan Elasticsearch clusters
- `stdin` - Scan from standard input
- `multi-scan` - Scan multiple sources from configuration

Each subcommand can have options that you can see with the `--help` flag:

```bash
offensiveboar git --help
offensiveboar jira --help
offensiveboar filesystem --help
```

## Jira Scanning

OffensiveBoar supports **Jira Cloud** and **Jira Server/Data Center** with three authentication modes.

### Authentication modes

| Mode | Flags | When to use |
|------|-------|-------------|
| Cloud (Basic Auth) | `--jira-email` + `--jira-token` | Jira Cloud (`*.atlassian.net`) |
| Server/DC Bearer | `--jira-token` | Server/DC with PAT (DC 8.14+) |
| Server/DC Basic Auth | `--jira-username` + `--jira-password` | On-prem, no token creation needed |

### Jira Cloud

```bash
offensiveboar jira \
  --jira-url https://your-domain.atlassian.net \
  --jira-email your@email.com \
  --jira-token YOUR_API_TOKEN
```

**Getting a Jira Cloud API token:**
1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
2. Click "Create API token"
3. Use it together with your Atlassian account email

### Jira Server/Data Center — username + password

Works on any Jira Server or Data Center without creating tokens:

```bash
offensiveboar jira \
  --jira-url https://jira.corp.local \
  --jira-username admin \
  --jira-password secret
```

### Jira Server/Data Center — Bearer token / PAT

Requires Data Center 8.14+ or Server with PAT support:

```bash
offensiveboar jira \
  --jira-url https://jira.corp.local \
  --jira-token YOUR_PAT
```

### Throttling

Use `--jira-throttle` to stay within API rate limits:

```bash
# Jira Cloud limit is ~10 req/s
offensiveboar jira --jira-url ... --jira-throttle 10rps

# Be polite on a production on-prem instance
offensiveboar jira --jira-url ... --jira-throttle 30rpm
```

Supported formats: `unlimited` (default), `10rps`, `5ps`, `30rpm`, `10rpm`, `1rpm`, `1rph`

### Scanning only recent activity

Use `--days N` to limit the scan to issues and comments updated in the last N days:

```bash
# Scan only issues updated in the last 2 days
offensiveboar jira --jira-url ... --jira-token ... --days 2

# Daily incremental scan
offensiveboar jira --jira-url ... --jira-token ... --days 1
```

The date filter is applied at the JQL level (server-side) so only matching issues are fetched. Comments within those issues are additionally filtered by their own timestamp.

### How It Works

1. Auto-detects Cloud vs Server/DC from the URL (or explicit flags)
2. Fetches all projects from the Jira instance
3. Retrieves matching issues with pagination (JQL `updated >= date` when `--days` is set)
4. Scans issue summaries, descriptions, and comments (plain text + ADF format)
5. Reports found secrets with direct links to the Jira issues

## Multi-Language Secret Detection

Use the `--custom-languages` flag to enable detection in multiple languages:

```bash
# English and Russian
offensiveboar filesystem /path/to/scan --custom-languages en,ru

# Multiple languages
offensiveboar filesystem /path/to/scan --custom-languages en,ru,es,fr,de
```

Supported language codes: `en`, `ru`, `es`, `fr`, `de`, `it`, `pt`, `ja`, `zh`, `ko`

# :question: FAQ

- **All I see is `🐷🔑🐷  OffensiveBoar. Unearth your secrets. 🐷🔑🐷` and the program exits, what gives?**
  - That means no secrets were detected

- **Why is the scan taking a long time when I scan a GitHub org?**
  - Unauthenticated GitHub scans have rate limits. To improve your rate limits, include the `--token` flag with a personal access token

- **It says a private key was verified, what does that mean?**
  - A verified result means OffensiveBoar confirmed the credential is valid by testing it against the service's API. For private keys, we've confirmed the key can be used live for SSH or SSL authentication.

- **Is there an easy way to ignore specific secrets?**
  - If the scanned source supports line numbers, then you can add a `offensiveboar:ignore` comment on the line containing the secret to ignore that secret.

- **How do I use multi-language detection?**
  - Use the `--custom-languages` flag with comma-separated language codes. Example: `--custom-languages en,ru`

- **What Jira permissions do I need?**
  - **Jira Cloud**: The account must have "Browse Projects" and "View Issues" permissions. Generate a token at https://id.atlassian.com/manage-profile/security/api-tokens
  - **Jira Server/DC (Bearer)**: The PAT must have access to the REST API and read permissions on projects/issues
  - **Jira Server/DC (Basic Auth)**: The user account must have "Browse Projects" and "View Issues" permissions — no token creation required

- **How do I know if I'm using Cloud or Server/DC?**
  - Cloud URLs end with `.atlassian.net` (e.g., `https://yourcompany.atlassian.net`)
  - Server/DC URLs are custom domains (e.g., `https://jira.yourcompany.com`)
  - OffensiveBoar auto-detects the type from the URL

- **How do I avoid hammering the Jira API?**
  - Use `--jira-throttle 10rps` for Cloud or `--jira-throttle 30rpm` for on-prem to limit request rate

- **How do I scan only recent changes?**
  - Use `--days N` to scan only issues updated in the last N days, e.g. `--days 1` for daily incremental scans

# :newspaper: What's New in This Fork

This fork of TruffleHog includes several enhancements:

- **Jira Integration**: Scan all issues in your Jira instance for leaked credentials — supports Cloud, Server/DC Bearer, and Server/DC Basic Auth (username+password, no token needed); configurable throttling and `--days` filter for incremental scans
- **Multi-Language Support**: Detect passwords and tokens in multiple languages (English, Russian, and more)
- **Enhanced Token Detection**: Improved detection of various token formats including Authorization headers
- **All Original Features**: Maintains all the powerful features from the original TruffleHog including:
  - Over 700 credential detectors with active verification
  - Native support for scanning GitHub, GitLab, Docker, filesystems, S3, GCS, Circle CI and Travis CI
  - Private key verification using Driftwood technology
  - Binary, document, and other file format scanning
  - GitHub Action and pre-commit hook support

## What is credential verification?

For every potential credential that is detected, we've painstakingly implemented programmatic verification against the API that we think it belongs to. Verification eliminates false positives and provides three result statuses:

- **verified**: Credential confirmed as valid and active by API testing
- **unverified**: Credential detected but not confirmed valid (may be invalid, expired, or verification disabled)  
- **unknown**: Verification attempted but failed due to errors, such as a network or API failure

For example, the AWS credential detector performs a `GetCallerIdentity` API call against the AWS API to verify if an AWS credential is active.

# :computer: Contributing

Contributions are very welcome! Please see our [contribution guidelines](CONTRIBUTING.md).

## Adding new secret detectors

We have published some [documentation and tooling to get started on adding new secret detectors](hack/docs/Adding_Detectors_external.md). Let's improve detection together!

# Use as a library

Currently, offensiveboar is in heavy development and no guarantees can be made on the stability of the public APIs at this time.

# License

Since v3.0, OffensiveBoar is released under an AGPL 3 license, included in [`LICENSE`](LICENSE). OffensiveBoar v3.0 uses none of the previous codebase, but care was taken to preserve backwards compatibility on the command line interface. The work previous to this release is still available licensed under GPL 2.0 in the history of this repository and the previous package releases and tags.

---

**Note**: This is a fork of [TruffleHog](https://github.com/trufflesecurity/trufflehog) with additional features for Jira integration and multi-language secret detection. All original TruffleHog functionality is preserved and enhanced.
