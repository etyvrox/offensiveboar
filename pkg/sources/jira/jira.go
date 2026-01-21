package jira

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/go-errors/errors"
	"github.com/go-logr/logr"
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

	endpoint        string
	token           string
	email           string
	isCloud         bool
	useBasicAuth    bool

	httpClient *http.Client
	mu         sync.Mutex

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
	
	// Determine installation type
	installationType := conn.GetInstallationType()
	if installationType == sourcespb.JiraInstallationType_JIRA_INSTALLATION_TYPE_AUTODETECT {
		// Auto-detect: check if URL contains .atlassian.net
		if strings.Contains(s.endpoint, ".atlassian.net") {
			s.isCloud = true
		}
	} else if installationType == sourcespb.JiraInstallationType_JIRA_INSTALLATION_TYPE_CLOUD {
		s.isCloud = true
	}

	// Handle authentication based on credential type
	if basicAuth := conn.GetBasicAuth(); basicAuth != nil {
		// Jira Cloud: Basic Auth with email:token
		s.email = basicAuth.Username
		s.token = basicAuth.Password
		s.useBasicAuth = true
		s.isCloud = true
	} else if token := conn.GetToken(); token != "" {
		// Jira Server/DC: Bearer token
		s.token = token
		s.useBasicAuth = false
	} else {
		return errors.New("Jira authentication credentials are required (token or basic auth)")
	}

	if s.endpoint == "" {
		return errors.New("Jira endpoint is required")
	}
	if s.token == "" {
		return errors.New("Jira token is required")
	}
	if s.isCloud && s.useBasicAuth && s.email == "" {
		return errors.New("Jira Cloud requires email address for Basic Auth")
	}

	s.httpClient = &http.Client{}

	return nil
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
	url := fmt.Sprintf("%s/rest/api/2/project", s.endpoint)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	// Set authentication header based on installation type
	if s.useBasicAuth {
		// Jira Cloud: Basic Auth with email:token
		auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", s.email, s.token)))
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))
	} else {
		// Jira Server/DC: Bearer token
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.token))
	}
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

// fetchIssues fetches all issues for a project with pagination
func (s *Source) fetchIssues(ctx context.Context, projectKey string) ([]JiraIssue, error) {
	// Jira Cloud requires POST with v3 API, Server/DC uses GET with v2 API
	if s.isCloud {
		return s.fetchIssuesV3POST(ctx, projectKey)
	}
	
	// Jira Server/DC: use v2 search endpoint with GET
	var allIssues []JiraIssue
	startAt := 0
	maxResults := 50

	for {
		jql := fmt.Sprintf("project=%s ORDER BY id ASC", projectKey)
		apiURL := fmt.Sprintf("%s/rest/api/2/search?jql=%s&fields=summary,description,comment&maxResults=%d&startAt=%d",
			s.endpoint, url.QueryEscape(jql), maxResults, startAt)

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			return nil, err
		}

		// Jira Server/DC: Bearer token
		req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", s.token))
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

// fetchIssuesV3POST fetches issues using POST method for Jira Cloud API v3
func (s *Source) fetchIssuesV3POST(ctx context.Context, projectKey string) ([]JiraIssue, error) {
	var allIssues []JiraIssue
	startAt := 0
	maxResults := 50

	for {
		jql := fmt.Sprintf("project=%s ORDER BY id ASC", projectKey)
		
		// Jira Cloud API v3 uses POST with JSON body
		requestBody := map[string]interface{}{
			"jql":        jql,
			"maxResults": maxResults,
			"startAt":    startAt,
			"fields":     []string{"summary", "description", "comment"},
		}
		
		jsonBody, err := json.Marshal(requestBody)
		if err != nil {
			return nil, err
		}

		apiURL := fmt.Sprintf("%s/rest/api/3/search/jql", s.endpoint)
		req, err := http.NewRequestWithContext(ctx, "POST", apiURL, strings.NewReader(string(jsonBody)))
		if err != nil {
			return nil, err
		}

		// Set authentication header
		auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", s.email, s.token)))
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		resp, err := s.httpClient.Do(req)
		if err != nil {
			return nil, err
		}

		if resp.StatusCode != http.StatusOK {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			return nil, fmt.Errorf("failed to fetch issues (v3 POST): status %d, body: %s", resp.StatusCode, string(body))
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
