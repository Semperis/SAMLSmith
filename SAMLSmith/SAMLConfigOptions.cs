using CommandLine;

namespace SAMLSmith;

[Verb("generate", HelpText = "Compute SAML Response by manually inserting values")]
public class SAMLConfigOptions
{
	[Option("pfxPath", HelpText = "Specify the path for the pfx file.")]
	public string PfxPath { get; set; } = "";

	[Option("pfxPassword", HelpText = "Specify the password for the pfx file.")]
	public string PfxPassword { get; set; } = "";

	[Option("idpid", HelpText = "The Identity Provider Identifier.")]
	public string IdentityProviderIdentifier { get; set; } = "";

	[Option("recipient", HelpText = "The recipient in the SAML response")]
	public string Recipient { get; set; } = "";

	[Option("subjectnameid", HelpText = "The subjectNameID in the SAML response")]
	public string SubjectNameId { get; set; } = "";

	[Option("audience", HelpText = "The audience in the SAML response")]
	public string Audience { get; set; } = "";

	[Option("attributes", HelpText = "The attributes/claims inside the assertion in the SAML response")]
	public string Attributes { get; set; } = "";

	[Option("inResponseTo", HelpText = "InReseponseTo")]
	public string InResponseTo { get; set; } = "";

}