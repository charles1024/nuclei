package core

import (
	"context"
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

// Executors are low level executors that deals with template execution on a target.

// executeAllSelfContained executes all self contained templates that do not use `target`.
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

// executeTemplateWithTargets executes a given template on x targets (with an internal target pool).
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

// executeTemplatesOnTarget executes given templates on a single target.
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

// executeTemplateOnInput performs template execution for a single input.
//
// Tech-stack filtering follows the diagram exactly:
//
//	┌─────────────────────────────────────────────────────────────────┐
//	│                     Nuclei Scan Entry                           │
//	│              One-time HTTP probe per host                       │
//	├─────────────────────────────┬───────────────────────────────────┤
//	│      Server Header          │        No Server Header           │
//	├──────────┬──────────────────┤  Run all possible app-URL detect. │
//	│ Matched  │  Not matched     │  If match → update app tag cache  │
//	│ known    │  (Tornado/IIS…)  │  Allow app tag cache for exec.    │
//	│ app tags │  Run app-URL     │  If no match → allow all templ.   │
//	│ Allow    │  detect.         │                                   │
//	│ cached   │  If no match →   │                                   │
//	│ server   │  allow all templ.│                                   │
//	│ tags     │                  │                                   │
//	└──────────┴──────────────────┴───────────────────────────────────┘
func (e *Engine) executeTemplateOnInput(ctx context.Context, template *templates.Template, value *contextargs.MetaInput) (bool, error) {
	ctxArgs := contextargs.New(ctx)
	ctxArgs.MetaInput = value
	scanCtx := scan.NewScanContext(ctx, ctxArgs)

	// ── Step 1: One-time HTTP probe (server header detection) ─────────────────
	// Fires once per host; result is cached for all subsequent templates.
	// ProbeHost is defined on the cache itself so tmplexec can share the same path.
	if e.HostTechCache != nil && !e.HostTechCache.HasHint(value.Input) {
		e.HostTechCache.ProbeHost(value.Input)
	}

	// ── Step 2: App-URL detection (for unrecognised / no server header) ───────
	// Runs once per host when the server header branch could not supply a tag set
	// (ProbeHasServerNoMatch) or when there was no server header (ProbeNoServerHeader).
	if e.HostTechCache != nil && e.HostTechCache.NeedsAppDetection(value.Input) {
		gologger.Debug().Msgf("[tech-filter] Running app-URL detection for host '%s'", value.Input)
		e.HostTechCache.RunAppDetection(value.Input)
	}

	// ── Step 3: Template filtering ────────────────────────────────────────────
	if e.HostTechCache != nil {
		tags := template.Info.Tags.ToSlice()
		versionRanges := make(map[string]interface{})
		if template.Info.Metadata != nil {
			if ranges, ok := template.Info.Metadata["version-ranges"].(map[string]interface{}); ok {
				versionRanges = ranges
			}
		}

		gologger.Debug().Msgf("[tech-filter] Template '%s' tags=%v version-ranges=%v host='%s'",
			template.ID, tags, versionRanges, value.Input)

		if e.HostTechCache.ShouldSkipTemplateWithVersion(value.Input, tags, versionRanges) {
			gologger.Debug().Msgf(
				"[tech-filter] SKIPPED template '%s' for host '%s' (server='%s', version='%s')",
				template.ID, value.Input,
				e.HostTechCache.GetServerHeader(value.Input),
				e.HostTechCache.GetVersion(value.Input),
			)
			return false, nil
		}

		gologger.Debug().Msgf("[tech-filter] ALLOW template '%s' for host '%s'", template.ID, value.Input)
	}

	// ── Step 4: Execute the template ──────────────────────────────────────────
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

	// ── Step 5: Learning – if matched, record the template's tags ─────────────
	if matched && e.HostTechCache != nil {
		tags := template.Info.Tags.ToSlice()
		e.HostTechCache.RecordTemplateMatch(value.Input, tags)
		gologger.Debug().Msgf("[tech-filter] Template '%s' MATCHED '%s' → learned tags: %v",
			template.ID, value.Input, tags)
	}

	return matched, err
}