package core

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

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

// executeAllSelfContained executes all self contained templates
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

// executeTemplateWithTargets executes a given template on x targets
func (e *Engine) executeTemplateWithTargets(ctx context.Context, template *templates.Template, target provider.InputProvider, results *atomic.Bool) {
	if e.workPool == nil {
		e.workPool = e.GetWorkPool()
	}
	pool := e.workPool.InputPool(template.Type())
	workerCount := 1
	if pool != nil && pool.Size > 0 {
		workerCount = pool.Size
	}

	var index uint32

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

	cleanupInFlight := func(index uint32) {
		currentInfo.Lock()
		delete(currentInfo.InFlight, index)
		currentInfo.Unlock()
	}

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
			return false
		default:
		}

		var skip bool
		if resumeFromInfo.Completed {
			e.options.Logger.Debug().Msgf("[%s] Skipping \"%s\": Resume - Template already completed", template.ID, scannedValue.Input)
			skip = true
		} else if index < resumeFromInfo.SkipUnder {
			e.options.Logger.Debug().Msgf("[%s] Skipping \"%s\": Resume - Target already processed", template.ID, scannedValue.Input)
			skip = true
		} else if _, isInFlight := resumeFromInfo.InFlight[index]; isInFlight {
			e.options.Logger.Debug().Msgf("[%s] Repeating \"%s\": Resume - Target wasn't completed", template.ID, scannedValue.Input)
			skip = false
		} else if index > resumeFromInfo.DoAbove {
			skip = false
		}

		currentInfo.Lock()
		currentInfo.InFlight[index] = struct{}{}
		currentInfo.Unlock()

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

	currentInfo.Lock()
	currentInfo.Completed = true
	currentInfo.Unlock()
}

// executeTemplatesOnTarget execute given templates on given single target
func (e *Engine) executeTemplatesOnTarget(ctx context.Context, alltemplates []*templates.Template, target *contextargs.MetaInput, results *atomic.Bool) {
	wp := e.GetWorkPool()
	defer wp.Wait()

	for _, tpl := range alltemplates {
		select {
		case <-ctx.Done():
			return
		default:
		}

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

func (e *Engine) probeHostTech(input string) {
    client := &http.Client{
        Timeout: 3 * time.Second,
        CheckRedirect: func(req *http.Request, via []*http.Request) error {
            return http.ErrUseLastResponse
        },
    }
    targetURL := input
    if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
        targetURL = "http://" + targetURL
    }
    resp, err := client.Get(targetURL)
    if err == nil && resp != nil {
        defer resp.Body.Close()
        e.HostTechCache.RecordServerHeaderAndProbe(input, resp)
    } else {
        e.HostTechCache.RecordNoServerHeader(input)
    }
}

// executeTemplateOnInput performs template execution for a single input
func (e *Engine) executeTemplateOnInput(ctx context.Context, template *templates.Template, value *contextargs.MetaInput) (bool, error) {
	ctxArgs := contextargs.New(ctx)
	ctxArgs.MetaInput = value
	scanCtx := scan.NewScanContext(ctx, ctxArgs)

	// Tech-stack probe: ONE-TIME per host
	if e.HostTechCache != nil && !e.HostTechCache.HasHint(value.Input) {
		client := &http.Client{
			Timeout: 3 * time.Second,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		
		targetURL := value.Input
		if !strings.HasPrefix(targetURL, "http://") && !strings.HasPrefix(targetURL, "https://") {
			targetURL = "http://" + targetURL
		}
		
		resp, err := client.Get(targetURL)
		if err == nil && resp != nil {
			defer resp.Body.Close()
			
			// FAST: Detect both server + application from single response
			e.HostTechCache.RecordServerHeaderAndProbe(value.Input, resp)
		} else {
			e.HostTechCache.RecordNoServerHeader(value.Input)
		}
	}

	// Tech-stack based template filtering
	if e.HostTechCache != nil {
		tags := template.Info.Tags.ToSlice()
		
		if e.HostTechCache.ShouldSkipTemplate(value.Input, tags) {
			gologger.Debug().Msgf("[tech-filter] SKIPPED template '%s' for host '%s'",
				template.ID, value.Input)
			return false, nil
		}
	}

	// Execute the template
	switch template.Type() {
	case types.WorkflowProtocol:
		return e.executeWorkflow(scanCtx, template.CompiledWorkflow), nil
	default:
		if e.Callback != nil {
			results, err := template.Executer.ExecuteWithResults(scanCtx)
			if err != nil {
				return false, err
			}
			for _, result := range results {
				e.Callback(result)
			}
			return len(results) > 0, nil
		}
		return template.Executer.Execute(scanCtx)
	}
}