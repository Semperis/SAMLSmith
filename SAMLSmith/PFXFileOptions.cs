using CommandLine;

namespace SAMLSmith;

[Verb("generatePFX", HelpText = "Compute SAML Response by the use of a JSON file")]
public class PFXFileOptions
{
	[Option("encryptedPFXPath", Required = false, HelpText = "Encrypted PFX File in binary form.")]
	public string EncryptedPfxBinaryForm { get; set; } = "";

	[Option("dkmKeyPath", Required = false, HelpText = "DKM key in binary form.")]
	public string DKMKeyPath { get; set; } = "";

	[Option("pfxOutputPath", Required = false, HelpText = "Output path for PFX.")]
	public string PfxOutputPath { get; set; } = "";


}