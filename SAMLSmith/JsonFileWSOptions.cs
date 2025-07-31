using CommandLine;

namespace SAMLSmith;

[Verb("generateWSJSON", HelpText = "Compute SAML Response by the use of a JSON file")]
public class JsonFileWSOptions
{
	[Option("jsonFile", Required = false, HelpText = "Load Json with SAML configurations.")]
	public string JsonFile { get; set; } = "";
}