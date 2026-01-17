package custom

import (
	"context"
	"testing"

	"github.com/etyvrox/offensiveboar/v3/pkg/detectors"
)

func TestCustomDetector_Keywords(t *testing.T) {
	scanner := &Scanner{}
	// Default should include English
	keywords := scanner.Keywords()
	
	// Should include JWT keywords and at least English password
	if len(keywords) < 4 {
		t.Errorf("Expected at least 4 keywords, got %d", len(keywords))
	}
	
	foundPassword := false
	for _, keyword := range keywords {
		if keyword == "password" {
			foundPassword = true
			break
		}
	}
	if !foundPassword {
		t.Error("Expected English keyword 'password' not found in default keywords")
	}
	
	// Test with English language explicitly enabled
	scanner.SetLanguages([]string{"en"})
	keywords = scanner.Keywords()
	
	foundPassword = false
	for _, keyword := range keywords {
		if keyword == "password" {
			foundPassword = true
			break
		}
	}
	if !foundPassword {
		t.Error("Expected English keyword 'password' not found when 'en' is set")
	}
	
	// Test with both English and Russian
	scanner.SetLanguages([]string{"en", "ru"})
	keywords = scanner.Keywords()
	
	foundPassword = false
	foundRussian := false
	for _, keyword := range keywords {
		if keyword == "password" {
			foundPassword = true
		}
		if keyword == "пароль" {
			foundRussian = true
		}
	}
	if !foundPassword {
		t.Error("Expected English keyword 'password' not found when 'en,ru' is set")
	}
	if !foundRussian {
		t.Error("Expected Russian keyword 'пароль' not found when 'en,ru' is set")
	}
	
	// Test with Russian language only
	scanner.SetLanguages([]string{"ru"})
	keywords = scanner.Keywords()
	
	foundRussian = false
	for _, keyword := range keywords {
		if keyword == "пароль" {
			foundRussian = true
			break
		}
	}
	if !foundRussian {
		t.Error("Expected Russian keyword 'пароль' not found")
	}
}

func TestCustomDetector_PasswordPattern(t *testing.T) {
	scanner := &Scanner{}
	scanner.SetLanguages([]string{"en"}) // Enable English
	ctx := context.Background()
	
	testCases := []struct {
		name     string
		data     string
		expected int
	}{
		{
			name:     "password with equals",
			data:     "password=secret123",
			expected: 1,
		},
		{
			name:     "password with colon",
			data:     "password: secret456",
			expected: 1,
		},
		{
			name:     "password with colon and exclamation",
			data:     "password: Test123!",
			expected: 1,
		},
		{
			name:     "password with equals and exclamation",
			data:     "password=Password123!",
			expected: 1,
		},
		{
			name:     "password with space only",
			data:     "password Test123456",
			expected: 1,
		},
		{
			name:     "password case insensitive",
			data:     "PASSWORD=secret789",
			expected: 1,
		},
		{
			name:     "no password",
			data:     "username=test",
			expected: 0,
		},
		{
			name:     "password too short",
			data:     "password=abc",
			expected: 0,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results, err := scanner.FromData(ctx, false, []byte(tc.data))
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			passwordCount := 0
			for _, result := range results {
				if result.ExtraData["type"] == "password" {
					passwordCount++
				}
			}
			
			if passwordCount != tc.expected {
				t.Errorf("Expected %d password results, got %d", tc.expected, passwordCount)
			}
		})
	}
}

func TestCustomDetector_RussianPasswordPattern(t *testing.T) {
	scanner := &Scanner{}
	scanner.SetLanguages([]string{"ru"}) // Enable Russian
	ctx := context.Background()

	testCases := []struct {
		name     string
		data     string
		expected int
	}{
		{
			name:     "Russian password with equals",
			data:     "пароль=секрет123",
			expected: 1,
		},
		{
			name:     "Russian password with colon",
			data:     "пароль: секрет456",
			expected: 1,
		},
		{
			name:     "Russian password with space only",
			data:     "пароль 123415215",
			expected: 1,
		},
		{
			name:     "Russian password with different form (паролем)",
			data:     "тестовый аккаунтс с паролем 4885235723 asdkqwdk",
			expected: 1,
		},
		{
			name:     "Russian password case insensitive",
			data:     "ПАРОЛЬ=секрет789",
			expected: 1,
		},
		{
			name:     "no Russian password",
			data:     "username=test",
			expected: 0,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			results, err := scanner.FromData(ctx, false, []byte(tc.data))
			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}
			
			passwordCount := 0
			for _, result := range results {
				if result.ExtraData["type"] == "password" {
					passwordCount++
				}
			}
			
			if passwordCount != tc.expected {
				t.Errorf("Expected %d password results, got %d", tc.expected, passwordCount)
			}
		})
	}
}

func TestCustomDetector_MultipleLanguages(t *testing.T) {
	scanner := &Scanner{}
	scanner.SetLanguages([]string{"en", "ru"}) // Enable both English and Russian
	ctx := context.Background()
	
	data := "password=secret123\nпароль=секрет456"
	results, err := scanner.FromData(ctx, false, []byte(data))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	passwordCount := 0
	for _, result := range results {
		if result.ExtraData["type"] == "password" {
			passwordCount++
		}
	}
	
	if passwordCount < 2 {
		t.Errorf("Expected at least 2 password results (one English, one Russian), got %d", passwordCount)
	}
}

func TestCustomDetector_JWTPattern(t *testing.T) {
	scanner := &Scanner{}
	ctx := context.Background()
	
	// Valid JWT token (example)
	jwtToken := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
	
	data := "token=" + jwtToken
	results, err := scanner.FromData(ctx, false, []byte(data))
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	
	jwtCount := 0
	for _, result := range results {
		if result.ExtraData["type"] == "jwt" {
			jwtCount++
		}
	}
	
	if jwtCount == 0 {
		t.Error("Expected at least one JWT result")
	}
}


func TestCustomDetector_SetLanguages(t *testing.T) {
	scanner := &Scanner{}
	
	// Test setting languages
	scanner.SetLanguages([]string{"en", "ru"})
	languages := scanner.GetEnabledLanguages()
	
	if len(languages) != 2 {
		t.Errorf("Expected 2 languages, got %d", len(languages))
	}
	
	// Test empty languages defaults to English
	scanner.SetLanguages([]string{})
	languages = scanner.GetEnabledLanguages()
	if len(languages) != 1 || languages[0] != "en" {
		t.Errorf("Expected default language 'en', got %v", languages)
	}
}

func TestCustomDetector_Type(t *testing.T) {
	scanner := &Scanner{}
	detectorType := scanner.Type()
	
	// DetectorType_Custom should be 1040 based on proto definition
	if detectorType.String() != "Custom" {
		t.Errorf("Expected detector type Custom, got %s", detectorType.String())
	}
}
