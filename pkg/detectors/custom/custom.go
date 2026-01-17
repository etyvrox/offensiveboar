package custom

import (
	"context"
	"strings"
	"sync"

	regexp "github.com/wasilibs/go-re2"

	"github.com/etyvrox/offensiveboar/v3/pkg/detectors"
	"github.com/etyvrox/offensiveboar/v3/pkg/pb/detectorspb"
)

type Scanner struct {
	enabledLanguages map[string]bool
	mu               sync.RWMutex
}

// Ensure the Scanner satisfies the interface at compile time.
var _ detectors.Detector = (*Scanner)(nil)

var (
	// Language-specific password keywords (base forms)
	passwordKeywords = map[string]string{
		"en": "password",
		"ru": "пароль",
		"es": "contraseña",
		"fr": "mot de passe",
		"de": "passwort",
		"it": "password",
		"pt": "senha",
		"ja": "パスワード",
		"zh": "密码",
		"ko": "비밀번호",
	}
	
	// English password word variants (different cases/forms)
	englishPasswordVariants = []string{"password", "passwords", "Password", "PASSWORD", "passWord", "PassWord"}
	
	// English token word variants (different cases/forms)
	englishTokenVariants = []string{"token", "tokens", "Token", "TOKEN", "toKen", "ToKen"}
	
	// Russian password word variants (different cases/forms)
	russianPasswordVariants = []string{"пароль", "паролем", "пароля", "паролей", "паролю", "паролях", "паролями"}

	// Pattern to match JWT tokens (eyJ prefix indicates base64 encoded JSON)
	jwtPat = regexp.MustCompile(`\b((?:eyJ|ewogIC|ewoid)[A-Za-z0-9_-]{12,}={0,2}\.(?:eyJ|ewo)[A-Za-z0-9_-]{12,}={0,2}\.[A-Za-z0-9_-]{12,})\b`)
	
	// Pattern to match Authorization: Bearer <token>
	bearerTokenPat = regexp.MustCompile(`(?i)authorization\s*:\s*bearer\s+([A-Za-z0-9_\-\.~+/=]{16,})`)
	
	// Pattern to match Authorization: Basic <base64>
	basicAuthPat = regexp.MustCompile(`(?i)authorization\s*:\s*basic\s+([A-Za-z0-9+/]{20,}={0,2})`)
)

// SetLanguages sets the enabled languages for password detection.
func (s *Scanner) SetLanguages(languages []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	if s.enabledLanguages == nil {
		s.enabledLanguages = make(map[string]bool)
	}
	
	// Clear existing languages
	for k := range s.enabledLanguages {
		delete(s.enabledLanguages, k)
	}
	
	// Set new languages (default to "en" if empty)
	if len(languages) == 0 {
		s.enabledLanguages["en"] = true
	} else {
		for _, lang := range languages {
			lang = strings.ToLower(strings.TrimSpace(lang))
			if _, exists := passwordKeywords[lang]; exists {
				s.enabledLanguages[lang] = true
			}
		}
	}
}

// GetEnabledLanguages returns the currently enabled languages.
func (s *Scanner) GetEnabledLanguages() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	languages := make([]string, 0, len(s.enabledLanguages))
	for lang := range s.enabledLanguages {
		languages = append(languages, lang)
	}
	return languages
}

// buildPasswordPatterns creates regex patterns for all enabled languages.
func (s *Scanner) buildPasswordPatterns() []*regexp.Regexp {
	s.mu.RLock()
	langs := make([]string, 0)
	
	// Default to English if no languages are set or map is nil
	if s.enabledLanguages == nil || len(s.enabledLanguages) == 0 {
		s.mu.RUnlock()
		langs = []string{"en"}
	} else {
		for lang := range s.enabledLanguages {
			langs = append(langs, lang)
		}
		s.mu.RUnlock()
	}
	
	patterns := make([]*regexp.Regexp, 0, len(langs))
	for _, lang := range langs {
		keyword, exists := passwordKeywords[lang]
		if !exists || keyword == "" {
			// Skip if language not found in map
			continue
		}
		escapedKeyword := regexp.QuoteMeta(keyword)
		
		// For English, create patterns for all variants (including base form)
		if lang == "en" {
			// Create patterns for each password variant explicitly
			// Since (?i) makes patterns case-insensitive, each pattern will match any case
			// But we create explicit patterns for each variant to ensure maximum coverage
			for _, variant := range englishPasswordVariants {
				// Don't use QuoteMeta for English variants - they don't contain special regex chars
				// and we want case-insensitive matching to work properly
				variantLower := strings.ToLower(variant)
				// Pattern 1: variant followed by = or : (e.g., "Password=secret" or "PASSWORD: secret")
				// Using (?i) makes it case-insensitive, so it will match any case
				pattern1 := regexp.MustCompile(`(?i)` + variantLower + `\s*[=:]\s*(\S{8,128})`)
				patterns = append(patterns, pattern1)
				pattern2 := regexp.MustCompile(`(?i)(?:^|[\s\n\r]|[^a-zA-Z0-9_])` + variantLower + `\s+([^\s\n\r"'<>{}[\]()]{8,128})`)
				patterns = append(patterns, pattern2)
			}
			
			// Create patterns for each token variant
			for _, variant := range englishTokenVariants {
				variantLower := strings.ToLower(variant)
				// Pattern 1: variant followed by = or : (e.g., "Token=abc123" or "TOKEN: xyz789")
				// Tokens are typically longer, so we use minimum 16 characters
				pattern1 := regexp.MustCompile(`(?i)` + variantLower + `\s*[=:]\s*([A-Za-z0-9_\-\.~+/=]{16,128})`)
				patterns = append(patterns, pattern1)
				// Pattern 2: variant followed by whitespace
				pattern2 := regexp.MustCompile(`(?i)(?:^|[\s\n\r]|[^a-zA-Z0-9_])` + variantLower + `\s+([A-Za-z0-9_\-\.~+/=]{16,128})`)
				patterns = append(patterns, pattern2)
			}
		} else {
			pattern1 := regexp.MustCompile(`(?i)` + escapedKeyword + `\s*[=:]\s*(\S{8,128})`)
			patterns = append(patterns, pattern1)
			
			// Pattern 2: keyword followed by whitespace (e.g., "password secret" or "пароль 12345")
			// This pattern matches keyword + whitespace + password (without = or :)
			// Need word boundary for this case to avoid false positives
			pattern2 := regexp.MustCompile(`(?i)(?:^|[\s\n\r]|[^a-zA-Zа-яА-Я0-9_])` + escapedKeyword + `\s+([^\s\n\r"'<>{}[\]()]{8,128})`)
			patterns = append(patterns, pattern2)
		}
		
		// For Russian, also add patterns for different word forms
		if lang == "ru" {
			for _, variant := range russianPasswordVariants {
				if variant != keyword { // Skip base form as it's already added
					escapedVariant := regexp.QuoteMeta(variant)
					// Pattern with = or :
					pattern1 := regexp.MustCompile(`(?i)` + escapedVariant + `\s*[=:]\s*(\S{8,128})`)
					patterns = append(patterns, pattern1)
					// Pattern with whitespace
					pattern2 := regexp.MustCompile(`(?i)(?:^|[\s\n\r]|[^a-zA-Zа-яА-Я0-9_])` + escapedVariant + `\s+([^\s\n\r"'<>{}[\]()]{8,128})`)
					patterns = append(patterns, pattern2)
				}
			}
		}
	}
	
	return patterns
}

// Keywords are used for efficiently pre-filtering chunks.
func (s *Scanner) Keywords() []string {
	s.mu.RLock()
	langs := make([]string, 0)
	
	// Default to English if no languages are set or map is nil
	if s.enabledLanguages == nil || len(s.enabledLanguages) == 0 {
		s.mu.RUnlock()
		return []string{"password", "eyJ", "ewogIC", "ewoid"}
	}
	
	for lang := range s.enabledLanguages {
		langs = append(langs, lang)
	}
	s.mu.RUnlock()
	
	keywords := []string{"eyJ", "ewogIC", "ewoid"} // JWT keywords
	
	// Add keywords for enabled languages
	for _, lang := range langs {
		if keyword := passwordKeywords[lang]; keyword != "" {
			keywords = append(keywords, keyword)
		}
		
		// For English, also add all word variants
		if lang == "en" {
			keywords = append(keywords, englishPasswordVariants...)
			keywords = append(keywords, englishTokenVariants...)
			// Add Authorization header keywords
			keywords = append(keywords, "authorization", "Authorization", "AUTHORIZATION", "bearer", "Bearer", "BEARER", "basic", "Basic", "BASIC")
		}
		
		// For Russian, also add all word variants
		if lang == "ru" {
			keywords = append(keywords, russianPasswordVariants...)
		}
	}
	
	// Always include "password" as fallback for English detection
	// This ensures English passwords are detected even if language setup fails
	hasPassword := false
	for _, kw := range keywords {
		if kw == "password" {
			hasPassword = true
			break
		}
	}
	if !hasPassword {
		keywords = append(keywords, "password")
	}
	
	return keywords
}

// FromData will find and optionally verify custom secrets (passwords and JWTs) in a given set of bytes.
func (s *Scanner) FromData(ctx context.Context, verify bool, data []byte) (results []detectors.Result, err error) {
	dataStr := string(data)

	seenPasswords := make(map[string]struct{})
	seenJWTs := make(map[string]struct{})

	// Find password patterns for all enabled languages
	passwordPatterns := s.buildPasswordPatterns()
	
	// If no patterns, something is wrong
	if len(passwordPatterns) == 0 {
		// This shouldn't happen, but if it does, return empty results
		return results, nil
	}
	
	for _, pattern := range passwordPatterns {
		matches := pattern.FindAllStringSubmatch(dataStr, -1)
		for _, match := range matches {
			password := strings.TrimSpace(match[1])
			if len(password) < 8 {
				continue
			}

			if _, ok := seenPasswords[password]; ok {
				continue
			}
			seenPasswords[password] = struct{}{}

			// Create redacted version for display (show first 4 and last 4 chars)
			redacted := password
			if len(password) > 8 {
				redacted = password[:4] + "..." + password[len(password)-4:]
			} else {
				redacted = password[:2] + "..."
			}

			s1 := detectors.Result{
				DetectorType: detectorspb.DetectorType_Custom,
				Raw:          []byte(password),
				Redacted:     redacted,
				ExtraData: map[string]string{
					"type": "password",
				},
			}

			if verify {
				// For passwords, we can't verify without context, so mark as unverified
				s1.Verified = false
			}

			results = append(results, s1)
		}
	}

	// Find JWT tokens
	for _, matchGroups := range jwtPat.FindAllStringSubmatch(dataStr, -1) {
		jwtToken := matchGroups[1]

		if _, ok := seenJWTs[jwtToken]; ok {
			continue
		}
		seenJWTs[jwtToken] = struct{}{}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Custom,
			Raw:          []byte(jwtToken),
			Redacted:     jwtToken[:8] + "...",
			ExtraData: map[string]string{
				"type": "jwt",
			},
		}

		if verify {
			// JWT tokens cannot be verified without additional context
			s1.Verified = false
		}

		results = append(results, s1)
	}

	// Find Bearer tokens in Authorization headers
	for _, matchGroups := range bearerTokenPat.FindAllStringSubmatch(dataStr, -1) {
		token := strings.TrimSpace(matchGroups[1])
		
		if len(token) < 16 {
			continue
		}

		if _, ok := seenJWTs[token]; ok {
			continue
		}
		seenJWTs[token] = struct{}{}

		// Create redacted version
		redacted := token
		if len(token) > 16 {
			redacted = token[:8] + "..." + token[len(token)-8:]
		} else {
			redacted = token[:4] + "..."
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Custom,
			Raw:          []byte(token),
			Redacted:     redacted,
			ExtraData: map[string]string{
				"type": "bearer_token",
			},
		}

		if verify {
			s1.Verified = false
		}

		results = append(results, s1)
	}

	// Find Basic auth credentials in Authorization headers
	for _, matchGroups := range basicAuthPat.FindAllStringSubmatch(dataStr, -1) {
		basicAuth := strings.TrimSpace(matchGroups[1])
		
		if len(basicAuth) < 20 {
			continue
		}

		if _, ok := seenJWTs[basicAuth]; ok {
			continue
		}
		seenJWTs[basicAuth] = struct{}{}

		// Create redacted version
		redacted := basicAuth
		if len(basicAuth) > 20 {
			redacted = basicAuth[:8] + "..." + basicAuth[len(basicAuth)-8:]
		} else {
			redacted = basicAuth[:4] + "..."
		}

		s1 := detectors.Result{
			DetectorType: detectorspb.DetectorType_Custom,
			Raw:          []byte(basicAuth),
			Redacted:     redacted,
			ExtraData: map[string]string{
				"type": "basic_auth",
			},
		}

		if verify {
			s1.Verified = false
		}

		results = append(results, s1)
	}

	return results, nil
}


func (s Scanner) Type() detectorspb.DetectorType {
	return detectorspb.DetectorType_Custom
}

func (s *Scanner) Description() string {
	return "Custom detector that searches for password and token patterns in multiple languages, JWT tokens, and Authorization headers (Bearer and Basic)."
}

// CleanResults returns all results without filtering. This ensures that all detected
// passwords and JWTs are reported, not just the first one.
func (s *Scanner) CleanResults(results []detectors.Result) []detectors.Result {
	// Return all results - we want to see all detected passwords and JWTs
	return results
}

// ShouldCleanResultsIrrespectiveOfConfiguration returns true, so CleanResults
// is always called, regardless of filterUnverified setting.
func (s *Scanner) ShouldCleanResultsIrrespectiveOfConfiguration() bool {
	return true
}
