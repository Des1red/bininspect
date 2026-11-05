package analyzer

import "bininspect/internal/models"

func Engine() {
	var result models.ResultsModel

	result.Identity = Identity()
	result.Sources = Sources()
	result.Structure = Structure()

	result.Assembly = Assembly(result.Identity.Architecture)
	result.Assembly.StackRelations = StackRelations(result.Assembly)

	result.Functions, result.FunctionDefinitions = Functions(
		result.Assembly,
	)

	result.Security = Security()

	result.Findings = Findings(
		result.Functions,
		result.Security,
		result.Assembly.StackRelations...,
	)

	models.Results = result
}
