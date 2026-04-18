package core

import (
	"context"
	"sync"
	"sync/atomic"
	"time"
	"net/http"
	"strings"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/nuclei/v3/pkg/input/provider"
	"github.com/projectdiscovery/nuclei/v3/pkg/output"
	"github.com/projectdiscovery/nuclei/v3/pkg/protocols/common/contextargs"
	"github.com/projectdiscovery/nuclei/v3/pkg/scan"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates/types"
	generalTypes "github.com/projectdiscovery/nuclei/v3/pkg/types"
	syncutil "github.com/projectdiscovery/utils/sync"
)

// Executors are low level executors that deals with template execution on a target

// executeAllSelfContained executes all self contained templates that do not use `target`
func (e *Engine) executeAllSelfContained(ctx context.Context, alltemplates []*templates.Template, results *atomic.Bool, sg *sync.WaitGroup) {
	for _, v := range alltemplates {
		sg.Add(1)
		go func(template *templates.Template) {
			defer sg.Done()
			var err error
			var match bool
			ctx := scan.NewScanContext(ctx, contextargs.New(ctx))
			if e.Callback != nil {
				if results, err := template.Executer.ExecuteWithResults(ctx); err == nil {
					for _, result := range results {
						e.Callback(result)
					}
				}

				match = true
			} else {
				match, err = template.Executer.Execute(ctx)
			}
			if err != nil {
				e.options.Logger.Warning().Msgf("[%s] Could not execute step (self-contained): %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), err)
			}
			results.CompareAndSwap(false, match)
		}(v)
	}
}

// executeTemplateWithTargets executes a given template on x targets (with a internal targetpool(i.e concurrency))
func (e *Engine) executeTemplateWithTargets(ctx context.Context, template *templates.Template, target provider.InputProvider, results *atomic.Bool) {
	if e.workPool == nil {
		e.workPool = e.GetWorkPool()
	}
	// Bounded worker pool using input concurrency
	pool := e.workPool.InputPool(template.Type())
	workerCount := 1
	if pool != nil && pool.Size > 0 {
		workerCount = pool.Size
	}

	var (
		index uint32
	)

	e.executerOpts.ResumeCfg.Lock()
	currentInfo, ok := e.executerOpts.ResumeCfg.Current[template.ID]
	if !ok {
		currentInfo = &generalTypes.ResumeInfo{}
		e.executerOpts.ResumeCfg.Current[template.ID] = currentInfo
	}
	if currentInfo.InFlight == nil {
		currentInfo.InFlight = make(map[uint32]struct{})
	}
	resumeFromInfo, ok := e.executerOpts.ResumeCfg.ResumeFrom[template.ID]
	if !ok {
		resumeFromInfo = &generalTypes.ResumeInfo{}
		e.executerOpts.ResumeCfg.ResumeFrom[template.ID] = resumeFromInfo
	}
	e.executerOpts.ResumeCfg.Unlock()

	// track progression
	cleanupInFlight := func(index uint32) {
		currentInfo.Lock()
		delete(currentInfo.InFlight, index)
		currentInfo.Unlock()
	}

	// task represents a single target execution unit
	type task struct {
		index uint32
		skip  bool
		value *contextargs.MetaInput
	}

	tasks := make(chan task)
	var workersWg sync.WaitGroup
	workersWg.Add(workerCount)
	for i := 0; i < workerCount; i++ {
		go func() {
			defer workersWg.Done()
			for t := range tasks {
				func() {
					defer cleanupInFlight(t.index)
					select {
					case <-ctx.Done():
						return
					default:
					}
					if t.skip {
						return
					}

					match, err := e.executeTemplateOnInput(ctx, template, t.value)
					if err != nil {
						e.options.Logger.Warning().Msgf("[%s] Could not execute step on %s: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), t.value.Input, err)
					}
					results.CompareAndSwap(false, match)
				}()
			}
		}()
	}

	target.Iterate(func(scannedValue *contextargs.MetaInput) bool {
		select {
		case <-ctx.Done():
			return false // exit
		default:
		}

		// Best effort to track the host progression
		// skips indexes lower than the minimum in-flight at interruption time
		var skip bool
		if resumeFromInfo.Completed { // the template was completed
			e.options.Logger.Debug().Msgf("[%s] Skipping \"%s\": Resume - Template already completed", template.ID, scannedValue.Input)
			skip = true
		} else if index < resumeFromInfo.SkipUnder { // index lower than the sliding window (bulk-size)
			e.options.Logger.Debug().Msgf("[%s] Skipping \"%s\": Resume - Target already processed", template.ID, scannedValue.Input)
			skip = true
		} else if _, isInFlight := resumeFromInfo.InFlight[index]; isInFlight { // the target wasn't completed successfully
			e.options.Logger.Debug().Msgf("[%s] Repeating \"%s\": Resume - Target wasn't completed", template.ID, scannedValue.Input)
			// skip is already false, but leaving it here for clarity
			skip = false
		} else if index > resumeFromInfo.DoAbove { // index above the sliding window (bulk-size)
			// skip is already false - but leaving it here for clarity
			skip = false
		}

		currentInfo.Lock()
		currentInfo.InFlight[index] = struct{}{}
		currentInfo.Unlock()

		// Skip if the host has had errors
		if e.executerOpts.HostErrorsCache != nil && e.executerOpts.HostErrorsCache.Check(e.executerOpts.ProtocolType.String(), contextargs.NewWithMetaInput(ctx, scannedValue)) {
			skipEvent := &output.ResultEvent{
				TemplateID:    template.ID,
				TemplatePath:  template.Path,
				Info:          template.Info,
				Type:          e.executerOpts.ProtocolType.String(),
				Host:          scannedValue.Input,
				MatcherStatus: false,
				Error:         "host was skipped as it was found unresponsive",
				Timestamp:     time.Now(),
			}

			if e.Callback != nil {
				e.Callback(skipEvent)
			} else if e.executerOpts.Output != nil {
				_ = e.executerOpts.Output.Write(skipEvent)
			}
			return true
		}

		tasks <- task{index: index, skip: skip, value: scannedValue}
		index++
		return true
	})

	close(tasks)
	workersWg.Wait()

	// on completion marks the template as completed
	currentInfo.Lock()
	currentInfo.Completed = true
	currentInfo.Unlock()
}

// executeTemplatesOnTarget execute given templates on given single target
func (e *Engine) executeTemplatesOnTarget(ctx context.Context, alltemplates []*templates.Template, target *contextargs.MetaInput, results *atomic.Bool) {
	// all templates are executed on single target

	// wp is workpool that contains different waitgroups for
	// headless and non-headless templates
	// global waitgroup should not be used here
	wp := e.GetWorkPool()
	defer wp.Wait()

	for _, tpl := range alltemplates {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// resize check point - nop if there are no changes
		wp.RefreshWithConfig(e.GetWorkPoolConfig())

		var sg *syncutil.AdaptiveWaitGroup
		if tpl.Type() == types.HeadlessProtocol {
			sg = wp.Headless
		} else {
			sg = wp.Default
		}
		sg.Add()
		go func(template *templates.Template, value *contextargs.MetaInput, wg *syncutil.AdaptiveWaitGroup) {
			defer wg.Done()

			match, err := e.executeTemplateOnInput(ctx, template, value)
			if err != nil {
				e.options.Logger.Warning().Msgf("[%s] Could not execute step on %s: %s\n", e.executerOpts.Colorizer.BrightBlue(template.ID), value.Input, err)
			}
			results.CompareAndSwap(false, match)
		}(tpl, target, sg)
	}
}

// executeTemplateOnInput performs template execution for a single input and returns match status and error
func (e *Engine) executeTemplateOnInput(ctx context.Context, template *templates.Template, value *contextargs.MetaInput) (bool, error) {
	ctxArgs := contextargs.New(ctx)
	ctxArgs.MetaInput = value
	scanCtx := scan.NewScanContext(ctx, ctxArgs)

	// --- Tech-stack probe: ONE-TIME per host ---
	if e.HostTechCache != nil && !e.HostTechCache.HasHint(value.Input) {
		// Send a lightweight GET request to detect Server header
		client := &http.Client{
			Timeout: 2 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		
		// Build full URL if needed
		targetURL := value.Input
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			targetURL = "http://" + targetURL
		}
		
		// Create a GET request
		req, err := http.NewRequest("GET", targetURL, nil)
		if err == nil {
			resp, err := client.Do(req)
			if err == nil && resp != nil {
				defer resp.Body.Close()
				if serverHdr := resp.Header.Get("Server"); serverHdr != "" {
					e.HostTechCache.RecordServerHeader(value.Input, serverHdr)
				} else {
					e.HostTechCache.RecordNoServerHeader(value.Input)
				}
			} else {
				e.HostTechCache.RecordNoServerHeader(value.Input)
			}
		} else {
			e.HostTechCache.RecordNoServerHeader(value.Input)
		}
	}
	// --- end probe ---

	// --- Tech-stack based template filtering ---
	gologger.Debug().Msgf("[tech-filter] CHECK: Checking if should skip template '%s' for host '%s'", template.ID, value.Input)

	if e.HostTechCache != nil {
	tags := template.Info.Tags.ToSlice()

	// Get version ranges from template metadata
	versionRanges := make(map[string]interface{})
	if template.Info.Metadata != nil {
		if ranges, ok := template.Info.Metadata["version-ranges"].(map[string]interface{}); ok {
			versionRanges = ranges  // Keep the raw interface{} values
		}
	}

	gologger.Debug().Msgf("[tech-filter] Template '%s' has tags: %v, version-ranges: %v", 
		template.ID, tags, versionRanges)

	if e.HostTechCache.ShouldSkipTemplateWithVersion(value.Input, tags, versionRanges) {
		serverHdr := e.HostTechCache.GetServerHeader(value.Input)
		version := e.HostTechCache.GetVersion(value.Input)
		
		gologger.Debug().Msgf(
			"[tech-filter] SKIPPED template '%s' for host '%s' (server='%s', version='%s', no matching tags/version)",
			template.ID, 
			value.Input,
			serverHdr,
			version,
		)
		return false, nil
	} else {
		gologger.Debug().Msgf("[tech-filter] ALLOW: Template '%s' passed filter for host '%s'", 
			template.ID, value.Input)
	}
	}
	// --- end tech-stack filtering ---
	// Execute the template
	var matched bool
	var err error
	
	switch template.Type() {
	case types.WorkflowProtocol:
		matched = e.executeWorkflow(scanCtx, template.CompiledWorkflow)
	default:
		if e.Callback != nil {
			results, execErr := template.Executer.ExecuteWithResults(scanCtx)
			err = execErr
			if err == nil && len(results) > 0 {
				matched = true
				for _, result := range results {
					e.Callback(result)
				}
			}
		} else {
			matched, err = template.Executer.Execute(scanCtx)
		}
	}

	//If template matched, update cache with learned tags
	if matched && e.HostTechCache != nil {
		tags := template.Info.Tags.ToSlice()
		e.HostTechCache.RecordTemplateMatch(value.Input, tags)
		
		gologger.Debug().Msgf("[tech-filter] Template '%s' MATCHED on '%s' → learning tags: %v", 
			template.ID, value.Input, tags)
	}

	return matched, err
}