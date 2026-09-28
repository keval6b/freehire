package mcpoauth

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	oauth2errors "github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/strelov1/freehire/internal/platform/db"
)

// cimdCacheCap bounds the Client ID Metadata Document cache. Entries expire
// after ten minutes but a URL that is fetched once stays until something
// evicts it, so an unbounded map is a memory leak with a public lookup in front.
const cimdCacheCap = 256

// Store is the sqlc surface this server persists through. *db.Queries
// satisfies it; tests substitute a memory fake.
type Store interface {
	UpsertOAuthClient(ctx context.Context, arg db.UpsertOAuthClientParams) error
	GetOAuthClient(ctx context.Context, clientID string) (db.GetOAuthClientRow, error)
	InsertOAuthAuthCode(ctx context.Context, arg db.InsertOAuthAuthCodeParams) error
	GetOAuthAuthCode(ctx context.Context, codeHash string) (db.GetOAuthAuthCodeRow, error)
	ConsumeOAuthAuthCode(ctx context.Context, codeHash string) (int64, error)
	InsertOAuthGrant(ctx context.Context, arg db.InsertOAuthGrantParams) (db.InsertOAuthGrantRow, error)
	RotateOAuthGrantTokens(ctx context.Context, arg db.RotateOAuthGrantTokensParams) (db.RotateOAuthGrantTokensRow, error)
	UseOAuthGrantByAccessHash(ctx context.Context, accessTokenHash pgtype.Text) (db.UseOAuthGrantByAccessHashRow, error)
	GetOAuthGrantByRefreshHash(ctx context.Context, refreshTokenHash pgtype.Text) (db.GetOAuthGrantByRefreshHashRow, error)
	ListOAuthGrantsByUser(ctx context.Context, userID int64) ([]db.ListOAuthGrantsByUserRow, error)
	RevokeOAuthGrant(ctx context.Context, arg db.RevokeOAuthGrantParams) (int64, error)
	GetUserTokenVersion(ctx context.Context, id int64) (int32, error)
}

type clientRecord struct {
	id, name  string
	redirects []string
	until     time.Time
}

type clientStore struct {
	q       Store
	http    *http.Client
	mu      sync.Mutex
	cimd    map[string]clientRecord
	fetches []time.Time
}

// cimdFetchBudget is how many metadata documents one process may retrieve in
// a minute. Cache hits do not spend it. The consent page's server-side lookup
// shares one source address, so this budget is not an IP limiter.
const cimdFetchBudget = 30

func (s *clientStore) GetByID(ctx context.Context, id string) (oauth2.ClientInfo, error) {
	rec, err := s.lookup(ctx, id)
	if err != nil || rec.id == "" {
		return nil, err
	}
	return &models.Client{
		ID:     rec.id,
		Secret: "",
		Domain: strings.Join(rec.redirects, "\n"),
		Public: true,
	}, nil
}

func (s *clientStore) lookup(ctx context.Context, id string) (clientRecord, error) {
	if strings.HasPrefix(id, "https://") {
		return s.fetchCIMD(ctx, id)
	}
	row, err := s.q.GetOAuthClient(ctx, id)
	if errors.Is(err, pgx.ErrNoRows) {
		return clientRecord{}, nil
	}
	if err != nil {
		return clientRecord{}, err
	}
	return clientRecord{id: row.ClientID, name: row.ClientName, redirects: row.RedirectUris}, nil
}

func (s *clientStore) name(ctx context.Context, id string) string {
	rec, err := s.lookup(ctx, id)
	if err != nil || rec.name == "" {
		return id
	}
	return rec.name
}

type cimdDocument struct {
	ClientID     string   `json:"client_id"`
	ClientName   string   `json:"client_name"`
	RedirectURIs []string `json:"redirect_uris"`
}

func (s *clientStore) fetchCIMD(ctx context.Context, id string) (clientRecord, error) {
	s.mu.Lock()
	if rec, ok := s.cimd[id]; ok && time.Now().Before(rec.until) {
		s.mu.Unlock()
		return rec, nil
	}
	s.mu.Unlock()

	if !AllowedRedirect(id) || !strings.HasPrefix(id, "https://") {
		return clientRecord{}, nil
	}
	if !s.allowFetch() {
		return clientRecord{}, nil
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, id, nil)
	if err != nil {
		return clientRecord{}, nil
	}
	req.Header.Set("Accept", "application/json")
	// A redirect to another host can serve a document whose client_id is still
	// the URL we were asked for. The metadata fetch does not follow any.
	client := *s.http
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("mcp oauth: client metadata must not redirect")
	}
	resp, err := client.Do(req)
	if err != nil {
		return clientRecord{}, nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return clientRecord{}, nil
	}
	var doc cimdDocument
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&doc); err != nil {
		return clientRecord{}, nil
	}
	if doc.ClientID != id || doc.ClientName == "" || len(doc.RedirectURIs) == 0 {
		return clientRecord{}, nil
	}
	for _, uri := range doc.RedirectURIs {
		if !AllowedRedirect(uri) {
			return clientRecord{}, nil
		}
	}
	rec := clientRecord{id: doc.ClientID, name: doc.ClientName, redirects: doc.RedirectURIs, until: time.Now().Add(10 * time.Minute)}
	s.remember(rec)
	return rec, nil
}

func (s *clientStore) allowFetch() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	cutoff := now.Add(-time.Minute)
	kept := s.fetches[:0]
	for _, at := range s.fetches {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	s.fetches = kept
	if len(s.fetches) >= cimdFetchBudget {
		return false
	}
	s.fetches = append(s.fetches, now)
	return true
}

func (s *clientStore) remember(rec clientRecord) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	for id, cached := range s.cimd {
		if !now.Before(cached.until) {
			delete(s.cimd, id)
		}
	}
	if _, exists := s.cimd[rec.id]; !exists {
		for len(s.cimd) >= cimdCacheCap {
			for id := range s.cimd {
				delete(s.cimd, id)
				break
			}
		}
	}
	s.cimd[rec.id] = rec
}

type tokenStore struct {
	q        Store
	clients  *clientStore
	resource string
}

func extensionOf(info oauth2.TokenInfo) url.Values {
	ext, ok := info.(oauth2.ExtendableTokenInfo)
	if !ok || ext.GetExtension() == nil {
		return url.Values{}
	}
	return ext.GetExtension()
}

func (s *tokenStore) Create(ctx context.Context, info oauth2.TokenInfo) error {
	ext := extensionOf(info)
	if ext.Get("resource_mismatch") == "1" {
		return oauth2errors.ErrInvalidGrant
	}
	resource := ext.Get("resource")
	if resource != s.resource {
		return oauth2errors.ErrInvalidGrant
	}
	if access := info.GetAccess(); access != "" {
		return s.saveGrant(ctx, info, ext, resource)
	}
	if code := info.GetCode(); code != "" {
		return s.saveCode(ctx, info, resource)
	}
	return oauth2errors.ErrInvalidRequest
}

func (s *tokenStore) saveCode(ctx context.Context, info oauth2.TokenInfo, resource string) error {
	userID, err := strconv.ParseInt(info.GetUserID(), 10, 64)
	if err != nil {
		return oauth2errors.ErrInvalidRequest
	}
	version, err := s.q.GetUserTokenVersion(ctx, userID)
	if err != nil {
		return err
	}
	expires := info.GetCodeCreateAt().Add(info.GetCodeExpiresIn())
	return s.q.InsertOAuthAuthCode(ctx, db.InsertOAuthAuthCodeParams{
		CodeHash:            hashToken(info.GetCode()),
		ClientID:            info.GetClientID(),
		UserID:              userID,
		RedirectUri:         info.GetRedirectURI(),
		CodeChallenge:       info.GetCodeChallenge(),
		CodeChallengeMethod: string(info.GetCodeChallengeMethod()),
		Resource:            resource,
		Scope:               info.GetScope(),
		ExpiresAt:           pgtype.Timestamptz{Time: expires, Valid: true},
		TokenVersion:        version,
	})
}

func (s *tokenStore) saveGrant(ctx context.Context, info oauth2.TokenInfo, ext url.Values, resource string) error {
	accessHash := pgtype.Text{String: hashToken(info.GetAccess()), Valid: true}
	refreshHash := pgtype.Text{String: hashToken(info.GetRefresh()), Valid: info.GetRefresh() != ""}
	if id := ext.Get("grant_id"); id != "" {
		grantID, err := strconv.ParseInt(id, 10, 64)
		if err != nil {
			return oauth2errors.ErrInvalidGrant
		}
		row, err := s.q.RotateOAuthGrantTokens(ctx, db.RotateOAuthGrantTokensParams{
			ID: grantID, AccessTokenHash: accessHash, RefreshTokenHash: refreshHash,
		})
		if errors.Is(err, pgx.ErrNoRows) {
			return oauth2errors.ErrInvalidGrant
		}
		if err != nil {
			return err
		}
		clampExpiry(info, row.ExpiresAt.Time)
		return nil
	}
	userID, err := strconv.ParseInt(info.GetUserID(), 10, 64)
	if err != nil {
		return oauth2errors.ErrInvalidRequest
	}
	version, err := s.q.GetUserTokenVersion(ctx, userID)
	if err != nil {
		return err
	}
	// The code was read while the generation still matched. A bump between that
	// read and this insert would store the new generation and undo the sign-out.
	// A missing generation is the same refusal: this path only mints a grant
	// from a code, and GetByCode always sets the key.
	issued := ext.Get("code_token_version")
	if issued == "" || issued != strconv.FormatInt(int64(version), 10) {
		return oauth2errors.ErrInvalidGrant
	}
	deadline := time.Now().Add(GrantTTL)
	row, err := s.q.InsertOAuthGrant(ctx, db.InsertOAuthGrantParams{
		UserID:           userID,
		ClientID:         info.GetClientID(),
		ClientName:       s.clients.name(ctx, info.GetClientID()),
		ExpiresAt:        pgtype.Timestamptz{Time: deadline, Valid: true},
		TokenVersion:     version,
		AccessTokenHash:  accessHash,
		RefreshTokenHash: refreshHash,
		Resource:         resource,
		Scope:            info.GetScope(),
	})
	if err != nil {
		return err
	}
	ext.Set("grant_id", strconv.FormatInt(row.ID, 10))
	if e, ok := info.(oauth2.ExtendableTokenInfo); ok {
		e.SetExtension(ext)
	}
	clampExpiry(info, row.ExpiresAt.Time)
	return nil
}

// clampExpiry makes the library report the time left on the grant. Refresh
// rewrites the access token's create time to now and would otherwise advertise
// a fresh lifetime; the grant row's expires_at is the deadline.
func clampExpiry(info oauth2.TokenInfo, deadline time.Time) {
	left := time.Until(deadline)
	if left < time.Second {
		left = time.Second
	}
	now := time.Now()
	info.SetAccessCreateAt(now)
	info.SetAccessExpiresIn(left)
	if info.GetRefresh() != "" {
		info.SetRefreshCreateAt(now)
		info.SetRefreshExpiresIn(left)
	}
}

func (s *tokenStore) RemoveByCode(ctx context.Context, code string) error {
	if code == "" {
		return nil
	}
	n, err := s.q.ConsumeOAuthAuthCode(ctx, hashToken(code))
	if err != nil {
		return err
	}
	// The library consumes the code and then inserts the grant. A concurrent
	// exchange can read the same live code; only the update that matches a row
	// may continue.
	if n == 0 {
		return oauth2errors.ErrInvalidAuthorizeCode
	}
	return nil
}

func (s *tokenStore) RemoveByAccess(context.Context, string) error { return nil }

func (s *tokenStore) RemoveByRefresh(context.Context, string) error { return nil }

func (s *tokenStore) GetByCode(ctx context.Context, code string) (oauth2.TokenInfo, error) {
	row, err := s.q.GetOAuthAuthCode(ctx, hashToken(code))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oauth2errors.ErrInvalidAuthorizeCode
	}
	if err != nil {
		return nil, err
	}
	ti := models.NewToken()
	ti.SetCode(code)
	ti.SetClientID(row.ClientID)
	ti.SetUserID(strconv.FormatInt(row.UserID, 10))
	ti.SetRedirectURI(row.RedirectUri)
	ti.SetScope(row.Scope)
	ti.SetCodeChallenge(row.CodeChallenge)
	ti.SetCodeChallengeMethod(oauth2.CodeChallengeMethod(row.CodeChallengeMethod))
	left := time.Until(row.ExpiresAt.Time)
	if left < time.Second {
		left = time.Second
	}
	ti.SetCodeCreateAt(time.Now())
	ti.SetCodeExpiresIn(left)
	ti.SetExtension(url.Values{
		"resource":           {row.Resource},
		"code_token_version": {strconv.FormatInt(int64(row.TokenVersion), 10)},
	})
	return ti, nil
}

func (s *tokenStore) GetByAccess(ctx context.Context, access string) (oauth2.TokenInfo, error) {
	row, err := s.q.UseOAuthGrantByAccessHash(ctx, pgtype.Text{String: hashToken(access), Valid: true})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oauth2errors.ErrInvalidAccessToken
	}
	if err != nil {
		return nil, err
	}
	if row.Resource != s.resource {
		return nil, oauth2errors.ErrInvalidAccessToken
	}
	ti := models.NewToken()
	ti.SetAccess(access)
	ti.SetClientID(row.ClientID)
	ti.SetUserID(strconv.FormatInt(row.UserID, 10))
	ti.SetScope(row.Scope)
	clampExpiry(ti, row.ExpiresAt.Time)
	ti.SetExtension(url.Values{
		"resource": {row.Resource},
		"grant_id": {strconv.FormatInt(row.ID, 10)},
	})
	return ti, nil
}

func (s *tokenStore) GetByRefresh(ctx context.Context, refresh string) (oauth2.TokenInfo, error) {
	row, err := s.q.GetOAuthGrantByRefreshHash(ctx, pgtype.Text{String: hashToken(refresh), Valid: true})
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oauth2errors.ErrInvalidRefreshToken
	}
	if err != nil {
		return nil, err
	}
	if row.Resource != s.resource {
		return nil, oauth2errors.ErrInvalidRefreshToken
	}
	ti := models.NewToken()
	ti.SetRefresh(refresh)
	ti.SetClientID(row.ClientID)
	ti.SetUserID(strconv.FormatInt(row.UserID, 10))
	ti.SetScope(row.Scope)
	// Access stays empty. Refresh removes the previous access by that value,
	// and the hashes were already rotated in place, so there is nothing to delete.
	clampExpiry(ti, row.ExpiresAt.Time)
	ti.SetExtension(url.Values{
		"resource": {row.Resource},
		"grant_id": {strconv.FormatInt(row.ID, 10)},
	})
	return ti, nil
}
