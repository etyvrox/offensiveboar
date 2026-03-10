package jira

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
	"golang.org/x/time/rate"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/etyvrox/offensiveboar/v3/pkg/common"
	"github.com/etyvrox/offensiveboar/v3/pkg/context"
	"github.com/etyvrox/offensiveboar/v3/pkg/pb/source_metadatapb"
	"github.com/etyvrox/offensiveboar/v3/pkg/pb/sourcespb"
	"github.com/etyvrox/offensiveboar/v3/pkg/sources"
)

const SourceType = sourcespb.SourceType_SOURCE_TYPE_JIRA

type Source struct {
	name     string
	sourceId sources.SourceID
	jobId    sources.JobID
	verify   bool
	log      logr.Logger

	endpoint string
	// isCloud is true when the target is Jira Cloud (*.atlassian.net).
	// Cloud uses API v3 and Basic Auth as email:token.
	isCloud bool
	// token holds the API token (Cloud) or PAT/Bearer token (Server/DC).
	token string
	// email is used only for Jira Cloud Basic Auth (email:token).
	email string
	// username and password are used for Basic Auth on on-prem Server/DC instances.
	username string
	password string

	rateLimiter *rate.Limiter
	httpClient  *http.Client
	mu          sync.Mutex

	sources.Progress
	sources.CommonSourceUnitUnmarshaller
}

var _ sources.Source = (*Source)(nil)
var _ sources.SourceUnitUnmarshaller = (*Source)(nil)
var _ sources.SourceUnitEnumChunker = (*Source)(nil)

func (s *Source) Type() sourcespb.SourceType {
	return SourceType
}

func (s *Source) SourceID() sources.SourceID {
	return s.sourceId
}

func (s *Source) JobID() sources.JobID {
	return s.jobId
}

// SetThrottle configures a rate limiter capping requests to rps per second.
// Call after Init and before scanning begins. rps <= 0 disables throttling.
func (s *Source) SetThrottle(rps float64) {
	if rps <= 0 {
		s.rateLimiter = nil
		return
	}
	burst := int(rps)
	if burst < 1 {
		burst = 1
	}
	s.rateLimiter = rate.NewLimiter(rate.Limit(rps), burst)
}

func (s *Source) Init(aCtx context.Context, name string, jobId sources.JobID, sourceId sources.SourceID, verify bool, connection *anypb.Any, _ int) error {
	s.name = name
	s.jobId = jobId
	s.sourceId = sourceId
	s.verify = verify
	s.log = aCtx.Logger()

	var conn sourcespb.JIRA
	if err := anypb.UnmarshalTo(connection, &conn, proto.UnmarshalOptions{}); err != nil {
		return errors.WrapPrefix(err, "error unmarshalling connection", 0)
	}

	s.endpoint = strings.TrimSuffix(conn.Endpoint, "/")
	if s.endpoint == "" {
		return errors.New("Jira endpoint is required")
	}

	// Detect installation type: explicit setting or URL heuristic.
	installationType := conn.GetInstallationType()
	if installationType == sourcespb.JiraInstallationType_JIRA_INSTALLATION_TYPE_CLOUD {
		s.isCloud = true
	} else if installationType == sourcespb.JiraInstallationType_JIRA_INSTALLATION_TYPE_AUTODETECT {
		s.isCloud = strings.Contains(s.endpoint, ".atlassian.net")
	}

	switch cred := conn.GetCredential().(type) {
	case *sourcespb.JIRA_BasicAuth:
		if cred.BasicAuth == nil {
			return errors.New("Jira basic_auth credential is nil")
		}
		if s.isCloud {
			// Cloud: BasicAuth credential carries email (Username) and API token (Password).
			s.email = cred.BasicAuth.Username
			s.token = cred.BasicAuth.Password
			if s.email == "" || s.token == "" {
				return errors.New("Jira Cloud requires both email and API token")
			}
		} else {
			// On-prem Server/DC: BasicAuth credential carries username and password.
			s.username = cred.BasicAuth.Username
			s.password = cred.BasicAuth.Password
			if s.username == "" || s.password == "" {
				return errors.New("Jira Basic Auth requires both username and password")
			}
		}
	case *sourcespb.JIRA_Token:
		s.token = cred.Token
		if s.token == "" {
			return errors.New("Jira token is required")
		}
	default:
		return errors.New("Jira credential must be a token (Bearer) or basic_auth (username+password / email+token)")
	}

	s.httpClient = &http.Client{}
	return nil
}

// setAuth applies the correct Authorization header for the current auth mode:
//   - Jira Cloud: Basic Auth with email:token
//   - Server/DC Bearer: Authorization: Bearer <token>
//   - Server/DC Basic: Basic Auth with username:password
func (s *Source) setAuth(req *http.Request) {
	if s.isCloud {
		req.SetBasicAuth(s.email, s.token)
	} else if s.token != "" {
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.token))
	} else {
		req.SetBasicAuth(s.username, s.password)
	}
}

// throttle waits until the rate limiter allows the next request.
// It is a no-op when no rate limiter is configured.
func (s *Source) throttle(ctx context.Context) error {
	if s.rateLimiter == nil {
		return nil
	}
	return s.rateLimiter.Wait(ctx)
}

// apiVersion returns the Jira REST API version to use.
func (s *Source) apiVersion() string {
	if s.isCloud {
		return "3"
	}
	return "2"
}

// JiraProject represents a Jira project
type JiraProject struct {
	Key  string `json:"key"`
	Name string `json:"name"`
	ID   string `json:"id"`
}

// JiraIssue represents a Jira issue
type JiraIssue struct {
	ID     string                 `json:"id"`
	Key    string                 `json:"key"`
	Fields map[string]interface{} `json:"fields"`
}

// JiraSearchResponse represents the response from Jira search API
type JiraSearchResponse struct {
	Issues []JiraIssue `json:"issues"`
	Total  int         `json:"total"`
}

// fetchProjects fetches all projects from Jira
func (s *Source) fetchProjects(ctx context.Context) ([]JiraProject, error) {
	if err := s.throttle(ctx); err != nil {
		return nil, err
	}

	apiURL := fmt.Sprintf("%s/rest/api/%s/project", s.endpoint, s.apiVersion())
	req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
	if err != nil {
		return nil, err
	}

	s.setAuth(req)
	req.Header.Set("Accept", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("failed to fetch projects: status %d, body: %s", resp.StatusCode, string(body))
	}

	var projects []JiraProject
	if err := json.NewDecoder(resp.Body).Decode(&projects); err != nil {
		return nil, err
	}

	return projects, nil
}

// fetchIssues fetches all issues for a project with pagination.
// Jira Cloud uses the v3 /search/jql endpoint; Server/DC uses v2 /search.
func (s *Source) fetchIssues(ctx context.Context, projectKey string) ([]JiraIssue, error) {
	var allIssues []JiraIssue
	startAt := 0
	maxResults := 50

	for {
		if err := s.throttle(ctx); err != nil {
			return nil, err
		}

		jql := fmt.Sprintf("project=%s ORDER BY id ASC", projectKey)

		var apiURL string
		if s.isCloud {
			// Cloud API v3 uses /rest/api/3/search/jql
			params := url.Values{}
			params.Set("jql", jql)
			params.Set("startAt", fmt.Sprintf("%d", startAt))
			params.Set("maxResults", fmt.Sprintf("%d", maxResults))
			params.Set("fields", "summary,description,comment")
			apiURL = fmt.Sprintf("%s/rest/api/3/search/jql?%s", s.endpoint, params.Encode())
		} else {
			apiURL = fmt.Sprintf("%s/rest/api/2/search?jql=%s&fields=summary,description,comment&maxResults=%d&startAt=%d",
				s.endpoint, url.QueryEscape(jql), maxResults, startAt)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return nil, err
		}

		s.setAuth(req)
		req.Header.Set("Accept", "application/json")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("failed to fetch issues: status %d, body: %s", resp.StatusCode, string(body))
		}

		var searchResp JiraSearchResponse
		if err := json.NewDecoder(resp.Body).Decode(&searchResp); err != nil {
			resp.Body.Close()
			return nil, err
		}
		resp.Body.Close()

		allIssues = append(allIssues, searchResp.Issues...)

		if len(searchResp.Issues) < maxResults || startAt+maxResults >= searchResp.Total {
			break
		}

		startAt += maxResults
	}

	return allIssues, nil
}

// buildIssueContent builds the content string from an issue
func (s *Source) buildIssueContent(issue JiraIssue) string {
	var content strings.Builder

	if fields, ok := issue.Fields["summary"].(string); ok {
		content.WriteString(fields)
		content.WriteString("\n")
	}

	if fields, ok := issue.Fields["description"].(string); ok {
		content.WriteString(fields)
		content.WriteString("\n")
	}

	// Handle comments
	if commentField, ok := issue.Fields["comment"].(map[string]interface{}); ok {
		if comments, ok := commentField["comments"].([]interface{}); ok {
			for _, comment := range comments {
				if commentMap, ok := comment.(map[string]interface{}); ok {
					// Body can be a string or an object (ADF format)
					if body, ok := commentMap["body"].(string); ok {
						content.WriteString(body)
						content.WriteString("\n")
					} else if bodyObj, ok := commentMap["body"].(map[string]interface{}); ok {
						// Try to extract text from ADF format
						if text, err := extractTextFromADF(bodyObj); err == nil && text != "" {
							content.WriteString(text)
							content.WriteString("\n")
						}
					}
				}
			}
		}
	}

	return content.String()
}

// extractTextFromADF extracts text from Atlassian Document Format (ADF)
func extractTextFromADF(adf map[string]interface{}) (string, error) {
	var text strings.Builder

	if content, ok := adf["content"].([]interface{}); ok {
		for _, node := range content {
			if nodeMap, ok := node.(map[string]interface{}); ok {
				if nodeType, ok := nodeMap["type"].(string); ok {
					if nodeType == "text" {
						if textContent, ok := nodeMap["text"].(string); ok {
							text.WriteString(textContent)
						}
					} else if nodeType == "paragraph" || nodeType == "heading" {
						// Recursively extract from nested content
						if nestedText, err := extractTextFromADF(nodeMap); err == nil {
							text.WriteString(nestedText)
							text.WriteString(" ")
						}
					}
				}
			}
		}
	}

	return text.String(), nil
}

func (s *Source) Chunks(ctx context.Context, chunksChan chan *sources.Chunk, _ ...sources.ChunkingTarget) error {
	// Fetch all projects
	projects, err := s.fetchProjects(ctx)
	if err != nil {
		return fmt.Errorf("failed to fetch projects: %w", err)
	}

	s.log.Info("fetched projects", "count", len(projects))

	totalIssues := 0
	for i, project := range projects {
		if common.IsDone(ctx) {
			return nil
		}

		s.SetProgressComplete(i, len(projects), fmt.Sprintf("Project: %s", project.Key), "")

		// Fetch all issues for this project
		issues, err := s.fetchIssues(ctx, project.Key)
		if err != nil {
			s.log.Error(err, "failed to fetch issues", "project", project.Key)
			continue
		}

		s.log.Info("fetched issues", "project", project.Key, "count", len(issues))

		// Process each issue
		for _, issue := range issues {
			if common.IsDone(ctx) {
				return nil
			}

			content := s.buildIssueContent(issue)
			if len(content) == 0 {
				continue
			}

			// Build issue URL
			issueURL := fmt.Sprintf("%s/browse/%s", s.endpoint, issue.Key)

			chunk := &sources.Chunk{
				SourceType: s.Type(),
				SourceName: s.name,
				SourceID:   s.SourceID(),
				JobID:      s.JobID(),
				Data:       []byte(content),
				SourceMetadata: &source_metadatapb.MetaData{
					Data: &source_metadatapb.MetaData_Jira{
						Jira: &source_metadatapb.Jira{
							Issue: issue.Key,
							Link:  issueURL,
						},
					},
				},
				Verify: s.verify,
			}

			select {
			case chunksChan <- chunk:
				totalIssues++
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	s.log.Info("completed scanning", "total_issues", totalIssues)
	return nil
}

func (s *Source) Enumerate(ctx context.Context, reporter sources.UnitReporter) error {
	projects, err := s.fetchProjects(ctx)
	if err != nil {
		return err
	}

	for _, project := range projects {
		unit := sources.CommonSourceUnit{ID: project.Key}
		if err := reporter.UnitOk(ctx, unit); err != nil {
			return err
		}
	}

	return nil
}

func (s *Source) ChunkUnit(ctx context.Context, unit sources.SourceUnit, reporter sources.ChunkReporter) error {
	projectKey, _ := unit.SourceUnitID()

	issues, err := s.fetchIssues(ctx, projectKey)
	if err != nil {
		return err
	}

	for _, issue := range issues {
		content := s.buildIssueContent(issue)
		if len(content) == 0 {
			continue
		}

		issueURL := fmt.Sprintf("%s/browse/%s", s.endpoint, issue.Key)

		chunk := sources.Chunk{
			SourceType: s.Type(),
			SourceName: s.name,
			SourceID:   s.SourceID(),
			JobID:      s.JobID(),
			Data:       []byte(content),
			SourceMetadata: &source_metadatapb.MetaData{
				Data: &source_metadatapb.MetaData_Jira{
					Jira: &source_metadatapb.Jira{
						Issue: issue.Key,
						Link:  issueURL,
					},
				},
			},
			Verify: s.verify,
		}

		if err := reporter.ChunkOk(ctx, chunk); err != nil {
			return err
		}
	}

	return nil
}
