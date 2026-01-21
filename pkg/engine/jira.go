package engine

import (
	"fmt"
	"runtime"
	"strings"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	credentialspb "github.com/etyvrox/offensiveboar/v3/pkg/pb/credentialspb"
	"github.com/etyvrox/offensiveboar/v3/pkg/context"
	"github.com/etyvrox/offensiveboar/v3/pkg/pb/sourcespb"
	"github.com/etyvrox/offensiveboar/v3/pkg/sources"
	"github.com/etyvrox/offensiveboar/v3/pkg/sources/jira"
)

// ScanJira scans a given Jira instance (supports both Cloud and Server/Data Center).
func (e *Engine) ScanJira(ctx context.Context, c sources.JiraConfig) (sources.JobProgressRef, error) {
	var conn anypb.Any
	
	// Determine installation type and set up credentials
	installationType := sourcespb.JiraInstallationType_JIRA_INSTALLATION_TYPE_AUTODETECT
	isCloudURL := strings.Contains(c.URL, ".atlassian.net")
	if isCloudURL {
		installationType = sourcespb.JiraInstallationType_JIRA_INSTALLATION_TYPE_CLOUD
		// Jira Cloud requires email for Basic Auth
		if c.Email == "" {
			return sources.JobProgressRef{}, fmt.Errorf("Jira Cloud requires --jira-email flag. For Cloud instances, use: --jira-url <url> --jira-email <email> --jira-token <token>")
		}
	}
	
	var connection *sourcespb.JIRA
	if c.Email != "" && (installationType == sourcespb.JiraInstallationType_JIRA_INSTALLATION_TYPE_CLOUD || isCloudURL) {
		// Jira Cloud: use Basic Auth with email:token
		connection = &sourcespb.JIRA{
			Endpoint:        c.URL,
			InstallationType: sourcespb.JiraInstallationType_JIRA_INSTALLATION_TYPE_CLOUD,
			Credential: &sourcespb.JIRA_BasicAuth{
				BasicAuth: &credentialspb.BasicAuth{
					Username: c.Email,
					Password: c.Token,
				},
			},
		}
	} else {
		// Jira Server/DC: use Bearer token
		connection = &sourcespb.JIRA{
			Endpoint:        c.URL,
			InstallationType: installationType,
			Credential: &sourcespb.JIRA_Token{
				Token: c.Token,
			},
		}
	}
	
	err := anypb.MarshalFrom(&conn, connection, proto.MarshalOptions{})
	if err != nil {
		ctx.Logger().Error(err, "failed to marshal jira connection")
		return sources.JobProgressRef{}, err
	}

	sourceName := "offensiveboar - jira"
	sourceID, jobID, _ := e.sourceManager.GetIDs(ctx, sourceName, jira.SourceType)

	jiraSource := &jira.Source{}
	if err := jiraSource.Init(ctx, sourceName, jobID, sourceID, true, &conn, runtime.NumCPU()); err != nil {
		return sources.JobProgressRef{}, err
	}
	return e.sourceManager.EnumerateAndScan(ctx, sourceName, jiraSource)
}
