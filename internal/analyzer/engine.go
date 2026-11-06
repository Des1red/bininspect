package analyzer

import (
	"bininspect/internal/analyzer/assembly"
	"bininspect/internal/analyzer/coverage"
	"bininspect/internal/analyzer/findings"
	"bininspect/internal/analyzer/flow"
	"bininspect/internal/analyzer/functions"
	"bininspect/internal/analyzer/identity"
	"bininspect/internal/analyzer/security"
	"bininspect/internal/analyzer/structure"
	"bininspect/internal/models"
)

func Engine() {
	var result models.ResultsModel

	result.Identity = identity.Analyze()
	result.Sources = coverage.Analyze()
	result.Structure = structure.Analyze()

	result.Assembly = assembly.Analyze(
		result.Identity.Architecture,
	)

	tracing := flow.Analyze(
		result.Assembly,
		models.Scope.Format,
	)

	result.Assembly.CallFlows = tracing.Calls
	result.Assembly.StackRelations = tracing.Relations

	result.Functions, result.FunctionDefinitions = functions.Analyze(
		result.Assembly,
	)

	result.Security = security.Analyze()

	result.Findings = findings.Analyze(
		result.Functions,
		result.Security,
		result.Assembly.StackRelations...,
	)

	models.Results = result
}
