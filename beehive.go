// The Beehive API is used to interact with user and robot data. Amongst other
// things, it supplies the Robot SecretKeys required to authenticate with the
// Nucleo API.

package neato

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"time"
)

const (
	beehiveAcceptHeader = "application/vnd.neato.beehive.v1+json"
	beehiveHost         = "beehive.neatocloud.com"

	platform    = "ios"
	tokenLength = 32
)

var (
	scopes = []string{"maps", "public_profile", "control_robots"}
)

func (t *token) queryValues() (*url.Values, error) {
	c, err := getCredentials()
	if err != nil {
		return nil, err
	}
	return &url.Values{
		"platform": []string{platform},
		"token":    []string{t.String()},
		"email":    []string{c.Username},
		"password": []string{c.Password},
	}, nil
}

// NewSession generates a new Session for use with the Neato Beehive API
func NewSession() (*Session, error) {
	t, err := newToken()
	if err != nil {
		return nil, err
	}
	v, err := t.queryValues()
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, (&url.URL{
		Scheme:   scheme,
		Host:     beehiveHost,
		Path:     "sessions",
		RawQuery: v.Encode(),
	}).String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", nucleoAcceptHeader)
	client := http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result Session
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// Refresh updates a *Session's authentication data
func (s *Session) Refresh() error {
	t, err := newToken()
	if err != nil {
		return err
	}
	v, err := t.queryValues()
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, (&url.URL{
		Scheme:   scheme,
		Host:     beehiveHost,
		Path:     "sessions",
		RawQuery: v.Encode(),
	}).String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", nucleoAcceptHeader)
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return json.NewDecoder(resp.Body).Decode(s)
}

// Session contains HTTP session data for use with the Neato Beehive API
type Session struct {
	AccessToken string    `json:"access_token"`
	CurrentTime time.Time `json:"current_time"`
	client      http.Client
}

// User is a user on the Neato systems with access to zero or more resources
type User struct {
	ID          string    `json:"id"`
	FirstName   string    `json:"first_name"`
	LastName    string    `json:"last_name"`
	Company     string    `json:"company"`
	Locale      string    `json:"locale"`
	PhoneNumber string    `json:"phone_number"`
	Street1     string    `json:"street_1"`
	Street2     string    `json:"street_2"`
	City        string    `json:"city"`
	PostCode    string    `json:"post_code"`
	Province    string    `json:"province"`
	StateRegion string    `json:"state_region"`
	CountryCode string    `json:"country_code"`
	Developer   bool      `json:"developer"`
	Email       string    `json:"email"`
	Newsletter  bool      `json:"newsletter"`
	CreatedAt   time.Time `json:"created_at"`
	VerifiedAt  time.Time `json:"verified_at"`
}

func newToken() (*token, error) {
	key := make([]byte, tokenLength)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	hexKey := make([]byte, hex.EncodedLen(len(key)))
	_ = hex.Encode(hexKey, key)
	return &token{hexKey}, nil
}

type token struct {
	value []byte
}

func (t *token) String() string {
	if t != nil {
		return string(t.value)
	}
	return ""
}

func (s *Session) bearer() string {
	return fmt.Sprintf("Bearer %s", s.AccessToken)
}

// A Robot corresponds to the data and controls for a physical robot
type Robot struct {
	Serial      string    `json:"serial"`
	Prefix      string    `json:"prefix"`
	Name        string    `json:"name"`
	Model       string    `json:"model"`
	SecretKey   string    `json:"secret_key"`
	PurchasedAt time.Time `json:"purchased_at"`
	LinkedAt    time.Time `json:"linked_at"`
	Traits      []string  `json:"traits"`
}

func (s *Session) setHeaders(req *http.Request) {
	req.Header.Set("Accept", beehiveAcceptHeader)
	req.Header.Set("Authorization", s.bearer())
}

// MapsResult contains details about the maps available on a Robot
type MapsResult struct {
	Stats struct{} `json:"stats"`
	Maps  []Map    `json:"maps"`
}

// Map is a single map, as stored on a Robot
type Map struct {
	Version                        int       `json:"version"`
	ID                             string    `json:"id"`
	URL                            string    `json:"url"`
	URLValidForSeconds             int       `json:"url_valid_for_seconds"`
	RunID                          string    `json:"run_id"`
	Status                         string    `json:"status"`
	LaunchedFrom                   string    `json:"launched_from"`
	Error                          string    `json:"error"`
	Category                       int       `json:"category"`
	Mode                           int       `json:"mode"`
	Modifier                       int       `json:"modifier"`
	StartAt                        time.Time `json:"start_at"`
	EndAt                          time.Time `json:"end_at"`
	EndOrientationRelativeDegrees  int       `json:"end_orientation_relative_degrees"`
	RunChargeAtStart               int       `json:"run_charge_at_start"`
	RunChargeAtEnd                 int       `json:"run_charge_at_end"`
	SuspendedCleaningChargingCount int       `json:"suspended_cleaning_charging_count"`
	TimeInSuspendedCleaning        int       `json:"time_in_suspended_cleaning"`
	TimeInError                    int       `json:"time_in_error"`
	TimeInPause                    int       `json:"time_in_pause"`
	CleanedArea                    float64   `json:"cleaned_area"`
	BaseCount                      int       `json:"base_count"`
	IsDocked                       bool      `json:"is_docked"`
	Delocalized                    bool      `json:"delocalized"`
}

func (s *Session) exec(method, path string) (*http.Response, error) {
	req, err := http.NewRequest(method, (&url.URL{
		Scheme: "https",
		Host:   beehiveHost,
		Path:   path,
	}).String(), nil)
	if err != nil {
		return nil, err
	}
	s.setHeaders(req)
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	return resp, nil
}

// GetRobotMap retrieves a particular Map from a specific Robot
func (s *Session) GetRobotMap(robot, id string) (*Map, error) {
	r, err := s.exec("GET", path.Join("users/me/robots", robot, "maps",
		id))
	if err != nil {
		return nil, err
	}
	var result Map
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// GetUser returns the User for the account
func (s *Session) GetUser() (*User, error) {
	r, err := s.exec("GET", "users/me")
	if err != nil {
		return nil, err
	}
	var result User
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListRobots returns the Robots for the account
func (s *Session) ListRobots() ([]Robot, error) {
	r, err := s.exec("GET", "users/me/robots")
	if err != nil {
		return nil, err
	}
	var result []Robot
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}

// ListRobotMaps returns the maps for the specified robot
func (s *Session) ListRobotMaps(robot string) (*MapsResult, error) {
	r, err := s.exec("GET", path.Join("users/me/robots", robot, "maps"))
	if err != nil {
		return nil, err
	}
	var result MapsResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

// ListRobotPersistentMaps returns the persistent maps for the specified Robot
func (s *Session) ListRobotPersistentMaps(robot string) ([]Map, error) {
	r, err := s.exec("GET", path.Join("users/me/robots", robot,
		"persistent_maps"))
	if err != nil {
		return nil, err
	}
	var result []Map
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		return nil, err
	}
	return result, nil
}
