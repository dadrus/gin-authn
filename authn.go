package gin_authn

import (
	"encoding/json"
	"errors"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/square/go-jose"
	"net/http"
	"strings"
	"sync"
)

type cache struct {
	entries map[string]*jose.JSONWebKey
	mutex   *sync.RWMutex
}

func newCache() *cache {
	return &cache{
		entries: make(map[string]*jose.JSONWebKey),
		mutex:   &sync.RWMutex{},
	}
}

func (c *cache) get(key string) (*jose.JSONWebKey, bool) {
	c.mutex.RLock()
	val, p := c.entries[key]
	c.mutex.RUnlock()
	return val, p
}

func (c *cache) put(key string, value *jose.JSONWebKey) {
	c.mutex.Lock()
	c.entries[key] = value
	c.mutex.Unlock()
}

type Configuration struct {
	VerifyToken          bool
	DiscoveryUrl         string
	JwksUrl              string
	AccessTokenExtractor TokenExtractor
	IdTokenExtractor     TokenExtractor
}

type oidcAware struct {
	cache  *cache
	config Configuration
}

func OAuth2Aware(config ...Configuration) gin.HandlerFunc {
	var conf Configuration
	if len(config) > 0 {
		conf = config[0]
	} else {
		conf = Configuration{}
	}

	m := &oidcAware{
		cache:  newCache(),
		config: conf,
	}

	if m.config.AccessTokenExtractor == nil {
		m.config.AccessTokenExtractor = DefaultAccessTokenExtractor
	}

	if m.config.IdTokenExtractor == nil {
		m.config.IdTokenExtractor = DefaultIdTokenExtractor
	}

	return func(c *gin.Context) {
		if token, err := m.getToken(c, m.config.AccessTokenExtractor); err == nil {
			m.handleAccessToken(c, token)
		}

		if token, err := m.getToken(c, m.config.IdTokenExtractor); err == nil {
			m.handleIdToken(c, token)
		}

		c.Next()
	}
}

func (m *oidcAware) handleAccessToken(c *gin.Context, token *jwt.Token) {
	c.Set("access_token", token)

	claims := token.Claims.(jwt.MapClaims)
	scopes, present := claims["scp"]
	if !present {
		scopes, present = claims["scope"]
	}

	if present {
		c.Set("scopes", toStringSlice(scopes))
	}

	if subject, present := claims["sub"]; present {
		c.Set("subject", subject)
	}
}

func (m *oidcAware) handleIdToken(c *gin.Context, token *jwt.Token) {
	c.Set("id_token", token)
}

func (m *oidcAware) getValidationKey(token *jwt.Token) (interface{}, error) {
	claims := token.Claims.(jwt.MapClaims)
	issuer := claims["iss"].(string)
	kid := token.Header["kid"].(string)

	cacheKey := issuer + kid
	jwk, present := m.cache.get(cacheKey)
	if !present {
		// retrieve signing key
		jwks, err := downloadJwks(issuer + ".well-known/jwks.json")
		if err != nil {
			return nil, err
		}

		jwksEntry := jwks.Key(kid)
		if len(jwksEntry) == 0 {
			return nil, errors.New("no key found for given key id")
		}

		if jwksEntry[0].Algorithm != token.Header["alg"].(string) {
			return nil, errors.New("algorithm mismatch between token header and the algorithm n jwk")
		}

		// TODO: Check the use claim from the jwk. It shall at least contain "sig"

		jwk = &jwksEntry[0]
		m.cache.put(cacheKey, jwk)
	}

	// TODO: check whether certificates are present and check the chain for validity
	// if not present try to download the chain and check it then

	return jwk.Key, nil
}

func (m *oidcAware) getToken(c *gin.Context, tokenExtractor TokenExtractor) (*jwt.Token, error) {
	rawToken, err := tokenExtractor.Extract(c)
	if err != nil {
		return nil, err
	}

	var token *jwt.Token
	if m.config.VerifyToken {
		token, err = jwt.Parse(rawToken, m.getValidationKey)
	} else {
		token, _, err = new(jwt.Parser).ParseUnverified(rawToken, jwt.MapClaims{})
	}
	return token, err
}

type compositeExtractor []TokenExtractor

func (ce compositeExtractor) Extract(c *gin.Context) (string, error) {
	for _, e := range ce {
		if t, err := e.Extract(c); err == nil {
			return t, nil
		}
	}

	return "", errors.New("no token present")
}

func CompositeExtractor(extractor ...TokenExtractor) TokenExtractor {
	var chain compositeExtractor

	for _, e := range extractor {
		chain = append(chain, e)
	}

	return chain
}

type TokenExtractor interface {
	Extract(c *gin.Context) (string, error)
}

type HeaderExtractor string

func (e HeaderExtractor) Extract(c *gin.Context) (string, error) {
	var headerName string
	var headerValuePrefix string
	var adjIdx = 0

	vals := strings.Split(string(e), ":")
	headerName = strings.ToLower(strings.TrimSpace(vals[0]))
	if len(vals) == 2 {
		headerValuePrefix = strings.ToLower(strings.TrimSpace(vals[1]))
		adjIdx = 1
	}

	if val := c.GetHeader(headerName); len(val) != 0 &&
		strings.Index(strings.ToLower(val), headerValuePrefix) != -1 {
		pos := strings.Index(strings.ToLower(val), headerValuePrefix)
		adjPos := pos + len(headerValuePrefix) + adjIdx
		if adjPos >= len(val) {
			return "", errors.New("malformed header")
		} else {
			return val[adjPos:], nil
		}
	} else {
		return "", errors.New("no token present")
	}
}

type QueryExtractor string

func (qe QueryExtractor) Extract(c *gin.Context) (string, error) {
	if val := c.Query(strings.TrimSpace(string(qe))); len(val) != 0 {
		return val, nil
	} else {
		return "", errors.New("no token present")
	}
}

type PostFormExtractor string

func (e PostFormExtractor) Extract(c *gin.Context) (string, error) {
	if val := c.PostForm(strings.TrimSpace(string(e))); len(val) != 0 {
		return val, nil
	} else {
		return "", errors.New("no token present")
	}
}

type CookieExtractor string

func (e CookieExtractor) Extract(c *gin.Context) (string, error) {
	if val, err := c.Cookie(strings.TrimSpace(string(e))); err == nil {
		return val, nil
	} else {
		return "", errors.New("no token present")
	}
}

var DefaultAccessTokenExtractor = CompositeExtractor(
	HeaderExtractor("Authorization: Bearer"),
	PostFormExtractor("access_token"),
	QueryExtractor("access_token"))

var DefaultIdTokenExtractor = HeaderExtractor("X-Id-Token")

func downloadJwks(jwksUrl string) (*jose.JSONWebKeySet, error) {
	resp, err := http.Get(jwksUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var jwks jose.JSONWebKeySet
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		return nil, err
	}

	return &jwks, nil
}

func DenyAll() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

func ScopesAllowed(allowedScopes ...string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if roles, present := c.Get("scopes"); !present ||
			len(allowedScopes) == 0 || !containsAll(roles.([]string), allowedScopes) {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		c.Next()
	}
}
