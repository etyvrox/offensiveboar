package engine

import (
	"runtime"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/etyvrox/offensiveboar/v3/pkg/context"
	"github.com/etyvrox/offensiveboar/v3/pkg/pb/sourcespb"
	"github.com/etyvrox/offensiveboar/v3/pkg/sources"
	"github.com/etyvrox/offensiveboar/v3/pkg/sources/jira"
)

// ScanJira scans a given Jira instance.
func (e *Engine) ScanJira(ctx context.Context, c sources.JiraConfig) (sources.JobProgressRef, error) {
	connection := &sourcespb.JIRA{
		Endpoint: c.URL,
		Credential: &sourcespb.JIRA_Token{
			Token: c.Token,
		},
	}
	var conn anypb.Any
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
