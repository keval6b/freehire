package mcpoauth

import "testing"

func TestAllowedRedirect(t *testing.T) {
	ok := []string{
		"https://claude.ai/api/mcp/auth_callback",
		"http://127.0.0.1:33418/callback",
		"http://localhost:3000/cb",
		"http://[::1]:8080/cb",
		"cursor://anysphere.cursor-mcp/callback",
	}
	bad := []string{
		"",
		"https://example.com/cb*",
		"http://evil.example/cb",
		"http://127.0.0.1.evil.example/cb",
		"javascript:alert(1)",
		"data:text/html,hi",
		"file:///tmp/x",
		"https://user:pass@example.com/cb",
		"https://example.com/cb#frag",
	}
	for _, raw := range ok {
		if !AllowedRedirect(raw) {
			t.Errorf("AllowedRedirect(%q) = false, want true", raw)
		}
	}
	for _, raw := range bad {
		if AllowedRedirect(raw) {
			t.Errorf("AllowedRedirect(%q) = true, want false", raw)
		}
	}
}

func TestExactRedirectMatchesOneOfSeveral(t *testing.T) {
	base := "https://a.example/cb\nhttp://127.0.0.1:9/cb"
	if err := exactRedirect(base, "http://127.0.0.1:9/cb"); err != nil {
		t.Fatal(err)
	}
	if err := exactRedirect(base, "https://a.example/cb/extra"); err == nil {
		t.Fatal("a longer URI matched a prefix")
	}
	if err := exactRedirect(base, "http://evil.example/cb"); err == nil {
		t.Fatal("an unlisted redirect matched")
	}
}
