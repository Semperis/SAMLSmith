using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using CommandLine;
using CommandLine.Text;

namespace SAMLSmith;

public class Program
{
	public static void Main(string[] commandLine)
	{
		var arguments = new Parser()
			.ParseArguments<JsonFileOptions, SAMLConfigOptions, PFXFileOptions, JsonFileWSOptions>(commandLine);

		arguments
			.WithParsed<JsonFileOptions>(options => ProcessJson(options))
			.WithParsed<JsonFileWSOptions>(options => ProcessJsonWS(options))
			.WithParsed<SAMLConfigOptions>(options => ProcessSAML(options))
			.WithParsed<PFXFileOptions>(options => GeneratePFXFile(options))

			.WithNotParsed(error =>
			{
				var helpText = HelpText.AutoBuild(arguments,
					onError =>
					{
						onError.AdditionalNewLineAfterOption = false;
						return HelpText.DefaultParsingErrorsHandler(arguments, onError);
					},
					onExample => onExample
				);
				Console.Error.Write(helpText);
			});
	}


	static void ProcessJson(JsonFileOptions options)
	{
		var parsedArgs = ParseJsonAttributes(options.JsonFile);
		try
		{
			string pfxPassword = null;
			string inResponseTo = null;
			var pfxFilePath = parsedArgs["pfxPath"];

			// FIXED: Better password handling - check if key exists and has non-empty value
			if (parsedArgs.ContainsKey("pfxPassword") && !string.IsNullOrEmpty(parsedArgs["pfxPassword"]))
			{
				pfxPassword = parsedArgs["pfxPassword"];
				Console.WriteLine($"Using password for PFX: {pfxPassword}");
			}
			else
			{
				Console.WriteLine("No password specified for PFX");
			}

			if (parsedArgs.ContainsKey("inResponseTo"))
			{
				inResponseTo = parsedArgs["inResponseTo"];
			}
			var identityProviderIdentifier = parsedArgs["idpid"];
			var recipient = parsedArgs["recipient"];
			var subjectNameID = parsedArgs["subjectnameid"];
			var audience = parsedArgs["audience"];
			var attributes = parsedArgs["attributes"].Split(',')
				.Select(pair => pair.Split('='))
				.ToDictionary(keyValue => keyValue[0], keyValue => keyValue[1]);

			var samlResponse = SAMLResponseGenerator.Generate(
				pfxFilePath,
				pfxPassword,
				inResponseTo,
				identityProviderIdentifier,
				attributes,
				subjectNameID,
				recipient,
				audience
			);

			Console.WriteLine("Generated SAML response:");
			Console.WriteLine(samlResponse);
		}
		catch (KeyNotFoundException ex)
		{
			Console.Error.WriteLine("Missing required argument: {0}", ex.Message);
		}
	}

	static void ProcessJsonWS(JsonFileWSOptions options)
	{
		var parsedArgs = ParseJsonWSAttributes(options.JsonFile);
		try
		{
			string pfxPassword = null;
			string inResponseTo = null;
			var pfxFilePath = parsedArgs["pfxPath"];
			if (parsedArgs.ContainsKey("pfxPassword"))
			{
				pfxPassword = parsedArgs["pfxPassword"];
			}
			if (parsedArgs.ContainsKey("inResponseTo"))
			{
				inResponseTo = parsedArgs["inResponseTo"];
			}
			var identityProviderIdentifier = parsedArgs["idpid"];
			var recipient = parsedArgs["recipient"];
			var subjectNameID = parsedArgs["subjectnameid"];
			var audience = parsedArgs["audience"];
			Dictionary<string, string> attributes;

			// Handle attributes as either string or object format
			if (parsedArgs["attributes"] is string attributeString)
			{
				// Handle comma-separated string format: "key1=value1,key2=value2"
				// Fixed to preserve == padding in Base64 values
				attributes = attributeString.Split(',')
					.Select(pair => {
						var parts = pair.Split('=', 2); // Limit to 2 parts to preserve == in values
						return new { Key = parts[0], Value = parts.Length > 1 ? parts[1] : "" };
					})
					.ToDictionary(keyValue => keyValue.Key, keyValue => keyValue.Value);
			}
			else
			{
				// Handle object format from JSON
				var attributesJson = parsedArgs["attributes"].ToString();
				attributes = System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string>>(attributesJson);
			}

			var wsFederationResponse = WSFederationResponseGenerator.Generate(
				pfxFilePath,
				pfxPassword != null ? pfxPassword : null,  // Fixed: pass pfxPassword, not pfxFilePath
				inResponseTo != null ? inResponseTo : null,
				identityProviderIdentifier,
				attributes,
				subjectNameID,
				recipient,
				audience
			);

			Console.WriteLine("Generated WS-Federation response:");
			Console.WriteLine(wsFederationResponse);
		}
		catch (KeyNotFoundException ex)
		{
			Console.Error.WriteLine("Missing required argument: {0}", ex.Message);
		}
	}

	static void GeneratePFXFile(PFXFileOptions options)
	{
		try
		{
			var decryptor = new EncryptedPFXDecryptor(options.EncryptedPfxBinaryForm, options.DKMKeyPath, false);
			var decryptedPFX = decryptor.DecryptPFX();

			EncryptedPFXDecryptor.SavePFX(decryptedPFX, options.PfxOutputPath);

			Console.WriteLine($"Successfully decrypted PFX and saved to: {options.PfxOutputPath}");
			Console.WriteLine($"PFX size: {decryptedPFX.Length} bytes");
		}
		catch (Exception ex)
		{
			Console.WriteLine(ex.Message);
		}

	}

	static Dictionary<string, string> ParseJsonAttributes(string filePath)
	{
		var result = new Dictionary<string, string>();

		var attributes = JsonConvert.DeserializeObject<Dictionary<string, object>>(
			File.ReadAllText(filePath)
		);
		foreach (var attribute in attributes!)
		{
			if (attribute.Key == "attributes")
			{
				var attributeObject = (JObject)attribute.Value;

				var keyValuePairs = attributeObject.Properties()
					.Select(property => $"{property.Name}={property.Value}");

				result[attribute.Key] = string.Join(",", keyValuePairs);
			}
			else
			{
				result[attribute.Key] = attribute.Value.ToString()!;
			}
		}


		return result;
	}

	static Dictionary<string, string> ParseJsonWSAttributes(string filePath)
	{
		var result = new Dictionary<string, string>();

		var attributes = JsonConvert.DeserializeObject<Dictionary<string, object>>(
			File.ReadAllText(filePath)
		);

		foreach (var attribute in attributes!)
		{
			result[attribute.Key] = attribute.Value.ToString()!;
		}


		return result;
	}

	static void ProcessSAML(SAMLConfigOptions options)
	{
		Console.WriteLine(options);

		try
		{
			var attributes = options.Attributes.Split(',')
				.Select(pair => pair.Split('='))
				.ToDictionary(keyValue => keyValue[0], keyValue => keyValue[1]);

			var samlResponse = SAMLResponseGenerator.Generate(
				options.PfxPath, options.PfxPassword, options.InResponseTo,
				options.IdentityProviderIdentifier, attributes,
				options.SubjectNameId, options.Recipient, options.Audience
			);

			Console.WriteLine("Generated SAML response:");
			Console.WriteLine(samlResponse);
		}
		catch (KeyNotFoundException ex)
		{
			Console.Error.WriteLine("Missing required argument: {0}", ex.Message);
		}
	}
}
