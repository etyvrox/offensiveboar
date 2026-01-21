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
OffensiveBoar can now scan Jira issues for leaked credentials:
- **Supports both Jira Cloud and Jira Server/Data Center**
- Scans all projects in your Jira instance
- Analyzes all issues, including summaries, descriptions, and comments
- Supports both plain text and ADF (Atlassian Document Format) content
- Provides direct links back to the Jira issues where secrets were found
- Automatically detects installation type (Cloud vs Server/DC) based on URL

**Jira Cloud example:**
```bash
offensiveboar jira --jira-url https://your-domain.atlassian.net --jira-email your-email@example.com --jira-token YOUR_API_TOKEN --custom-languages en,ru
```

**Jira Server/Data Center example:**
```bash
offensiveboar jira --jira-url https://your-jira-instance.com --jira-token YOUR_BEARER_TOKEN --custom-languages en,ru
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
offensiveboar jira --jira-url https://your-domain.atlassian.net --jira-email your-email@example.com --jira-token YOUR_API_TOKEN --custom-languages en,ru
```

**Jira Server/Data Center:**
```bash
offensiveboar jira --jira-url https://your-jira.com --jira-token YOUR_BEARER_TOKEN --custom-languages en,ru
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

OffensiveBoar supports both **Jira Cloud** and **Jira Server/Data Center** instances.

### Jira Cloud

For Jira Cloud instances (URLs ending with `.atlassian.net`), you need to provide your email and API token:

```bash
offensiveboar jira --jira-url https://your-domain.atlassian.net --jira-email your-email@example.com --jira-token YOUR_API_TOKEN
```

**Getting a Jira Cloud API token:**
1. Go to https://id.atlassian.com/manage-profile/security/api-tokens
2. Click "Create API token"
3. Copy the token and use it with your email address

### Jira Server/Data Center

For on-premise Jira instances, use a Bearer token:

```bash
offensiveboar jira --jira-url https://your-jira-instance.com --jira-token YOUR_BEARER_TOKEN
```

### With Multi-Language Support

Both Cloud and Server support multi-language detection:

```bash
# Cloud
offensiveboar jira --jira-url https://your-domain.atlassian.net --jira-email your-email@example.com --jira-token YOUR_API_TOKEN --custom-languages en,ru

# Server/DC
offensiveboar jira --jira-url https://your-jira-instance.com --jira-token YOUR_BEARER_TOKEN --custom-languages en,ru
```

### How It Works

The tool will:
1. Automatically detect installation type (Cloud vs Server/DC) based on URL
2. Use appropriate authentication method (Basic Auth for Cloud, Bearer for Server/DC)
3. Fetch all projects from your Jira instance
4. Retrieve all issues for each project with pagination
5. Scan issue summaries, descriptions, and comments (including ADF format)
6. Report any found secrets with direct links back to the Jira issues

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
  - **Jira Cloud**: Your API token needs permissions to read projects and issues. The user account associated with the email must have "Browse Projects" and "View Issues" permissions.
  - **Jira Server/DC**: Your Bearer token must have permissions to access the REST API and read projects/issues.
- **How do I know if I'm using Cloud or Server/DC?**
  - Cloud URLs typically end with `.atlassian.net` (e.g., `https://yourcompany.atlassian.net`)
  - Server/DC URLs are usually custom domains (e.g., `https://jira.yourcompany.com`)
  - OffensiveBoar automatically detects the type, but you can explicitly specify it if needed

# :newspaper: What's New in This Fork

This fork of TruffleHog includes several enhancements:

- **Jira Integration**: Scan all issues in your Jira instance for leaked credentials
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
