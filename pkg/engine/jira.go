package engine

import (
	"runtime"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/etyvrox/offensiveboar/v3/pkg/context"
	"github.com/etyvrox/offensiveboar/v3/pkg/pb/credentialspb"
	"github.com/etyvrox/offensiveboar/v3/pkg/pb/sourcespb"
	"github.com/etyvrox/offensiveboar/v3/pkg/sources"
	"github.com/etyvrox/offensiveboar/v3/pkg/sources/jira"
)

// ScanJira scans a given Jira instance. Supports three authentication modes:
//   - Jira Cloud (*.atlassian.net): --jira-email + --jira-token  → Basic Auth email:token, API v3
//   - Server/DC Bearer:             --jira-token only             → Authorization: Bearer <token>, API v2
//   - Server/DC Basic Auth:         --jira-username + --jira-password → Basic Auth, API v2
func (e *Engine) ScanJira(ctx context.Context, c sources.JiraConfig) (sources.JobProgressRef, error) {
	isCloudURL := strings.Contains(c.URL, ".atlassian.net")

	var (
		connection       *sourcespb.JIRA
		installationType = sourcespb.JiraInstallationType_JIRA_INSTALLATION_TYPE_AUTODETECT
	)

	if c.Email != "" || isCloudURL {
		// Jira Cloud: Basic Auth with email:token
		installationType = sourcespb.JiraInstallationType_JIRA_INSTALLATION_TYPE_CLOUD
		connection = &sourcespb.JIRA{
			Endpoint:         c.URL,
			InstallationType: installationType,
			Credential: &sourcespb.JIRA_BasicAuth{
				BasicAuth: &credentialspb.BasicAuth{
					Username: c.Email,
					Password: c.Token,
				},
			},
		}
	} else if c.Token != "" {
		// Server/DC: Bearer token / PAT
		connection = &sourcespb.JIRA{
			Endpoint:         c.URL,
			InstallationType: installationType,
			Credential: &sourcespb.JIRA_Token{
				Token: c.Token,
			},
		}
	} else {
		// Server/DC: Basic Auth with username:password
		connection = &sourcespb.JIRA{
			Endpoint:         c.URL,
			InstallationType: installationType,
			Credential: &sourcespb.JIRA_BasicAuth{
				BasicAuth: &credentialspb.BasicAuth{
					Username: c.Username,
					Password: c.Password,
				},
			},
		}
	}

	var conn anypb.Any
	if err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{}); err != nil {
		ctx.Logger().Error(err, "failed to marshal jira connection")
		return sources.JobProgressRef{}, err
	}

	sourceName := "offensiveboar - jira"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, jira.SourceType)

	jiraSource := &jira.Source{}
	if err := jiraSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return sources.JobProgressRef{}, err
	}

	if c.ThrottleRPS > 0 {
		jiraSource.SetThrottle(c.ThrottleRPS)
	}

	return e.sourceManager.EnumerateAndScan(ctx, sourceName, jiraSource)
}
