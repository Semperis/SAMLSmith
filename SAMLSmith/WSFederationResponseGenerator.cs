using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Text;
using System.Web;
using System.Text.RegularExpressions;

namespace SAMLSmith;

// Custom SignedXml class to handle AssertionID references properly
public class CustomSignedXml : SignedXml
{
    private readonly string _assertionId;

    public CustomSignedXml(XmlDocument document, string assertionId) : base(document)
    {
        _assertionId = assertionId;
    }

    public override XmlElement GetIdElement(XmlDocument document, string idValue)
    {
        // Remove the # prefix if present
        var id = idValue.StartsWith("#") ? idValue.Substring(1) : idValue;

        // If this matches our assertion ID, return the assertion element
        if (id == _assertionId)
        {
            // Find the assertion element by ID
            var assertionElement = document.SelectSingleNode($"//*[@AssertionID='{id}']") as XmlElement;
            if (assertionElement != null)
                return assertionElement;
        }

        // Fall back to default behavior
        return base.GetIdElement(document, idValue);
    }
}

public class WSFederationResponseGenerator
{
    public static string Generate(
        string pfxFilePath,
        string pfxPassword,
        string inResponseTo,
        string identityProviderIdentifier,
        Dictionary<string, string> attributes,
        string subjectNameID,
        string recipient,
        string audience
    )
    {
        try
        {
            var document = new XmlDocument();
            document.PreserveWhitespace = false;
            X509Certificate2 certificate = null;

            // Create WS-Trust RequestSecurityTokenResponse element
            var response = document.CreateElement("t", "RequestSecurityTokenResponse", "http://schemas.xmlsoap.org/ws/2005/02/trust");
            document.AppendChild(response);

            // Add Lifetime element
            var lifetime = document.CreateElement("t", "Lifetime", "http://schemas.xmlsoap.org/ws/2005/02/trust");
            response.AppendChild(lifetime);

            var created = document.CreateElement("wsu", "Created", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            created.InnerText = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            lifetime.AppendChild(created);

            var expires = document.CreateElement("wsu", "Expires", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd");
            expires.InnerText = DateTime.UtcNow.AddMinutes(60).ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
            lifetime.AppendChild(expires);

            // Add AppliesTo element
            var appliesToElement = document.CreateElement("wsp", "AppliesTo", "http://schemas.xmlsoap.org/ws/2004/09/policy");
            response.AppendChild(appliesToElement);

            var endpointReference = document.CreateElement("wsa", "EndpointReference", "http://www.w3.org/2005/08/addressing");
            appliesToElement.AppendChild(endpointReference);

            var address = document.CreateElement("wsa", "Address", "http://www.w3.org/2005/08/addressing");
            address.InnerText = audience;
            endpointReference.AppendChild(address);

            // Add RequestedSecurityToken element
            var requestedSecurityToken = document.CreateElement("t", "RequestedSecurityToken", "http://schemas.xmlsoap.org/ws/2005/02/trust");
            response.AppendChild(requestedSecurityToken);

            // Create SAML 1.1 Assertion
            var assertion = document.CreateElement("saml", "Assertion", "urn:oasis:names:tc:SAML:1.0:assertion");
            var assertionId = "_" + Guid.NewGuid().ToString();
            assertion.SetAttribute("MajorVersion", "1");
            assertion.SetAttribute("MinorVersion", "1");
            assertion.SetAttribute("AssertionID", assertionId);
            assertion.SetAttribute("Issuer", identityProviderIdentifier);
            assertion.SetAttribute("IssueInstant", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
            requestedSecurityToken.AppendChild(assertion);

            // Add Conditions element
            var conditions = document.CreateElement("saml", "Conditions", "urn:oasis:names:tc:SAML:1.0:assertion");
            conditions.SetAttribute("NotBefore", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
            conditions.SetAttribute("NotOnOrAfter", DateTime.UtcNow.AddMinutes(60).ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
            assertion.AppendChild(conditions);

            var audienceRestriction = document.CreateElement("saml", "AudienceRestrictionCondition", "urn:oasis:names:tc:SAML:1.0:assertion");
            conditions.AppendChild(audienceRestriction);

            var audienceElement = document.CreateElement("saml", "Audience", "urn:oasis:names:tc:SAML:1.0:assertion");
            audienceElement.InnerText = audience;
            audienceRestriction.AppendChild(audienceElement);

            // Add AttributeStatement
            var attributeStatement = document.CreateElement("saml", "AttributeStatement", "urn:oasis:names:tc:SAML:1.0:assertion");
            assertion.AppendChild(attributeStatement);

            // Add Subject to AttributeStatement
            var subject = document.CreateElement("saml", "Subject", "urn:oasis:names:tc:SAML:1.0:assertion");
            attributeStatement.AppendChild(subject);

            // Determine the NameIdentifier value - prefer ImmutableID if available
            string nameIdentifierValue = subjectNameID;
            if (attributes.ContainsKey("ImmutableID") && !string.IsNullOrEmpty(attributes["ImmutableID"]))
            {
                nameIdentifierValue = attributes["ImmutableID"];
            }
            else if (attributes.ContainsKey("immutableid") && !string.IsNullOrEmpty(attributes["immutableid"]))
            {
                nameIdentifierValue = attributes["immutableid"];
            }

            var nameIdentifier = document.CreateElement("saml", "NameIdentifier", "urn:oasis:names:tc:SAML:1.0:assertion");
            nameIdentifier.SetAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
            nameIdentifier.InnerText = nameIdentifierValue;
            subject.AppendChild(nameIdentifier);

            var subjectConfirmation = document.CreateElement("saml", "SubjectConfirmation", "urn:oasis:names:tc:SAML:1.0:assertion");
            subject.AppendChild(subjectConfirmation);

            var confirmationMethod = document.CreateElement("saml", "ConfirmationMethod", "urn:oasis:names:tc:SAML:1.0:assertion");
            confirmationMethod.InnerText = "urn:oasis:names:tc:SAML:1.0:cm:bearer";
            subjectConfirmation.AppendChild(confirmationMethod);

            // Add attributes
            foreach (var attribute in attributes)
            {
                var attributeElement = document.CreateElement("saml", "Attribute", "urn:oasis:names:tc:SAML:1.0:assertion");
                attributeElement.SetAttribute("AttributeName", attribute.Key);

                // Set appropriate namespace based on attribute name
                var attributeNamespace = GetAttributeNamespace(attribute.Key);
                attributeElement.SetAttribute("AttributeNamespace", attributeNamespace);

                attributeStatement.AppendChild(attributeElement);

                var attributeValue = document.CreateElement("saml", "AttributeValue", "urn:oasis:names:tc:SAML:1.0:assertion");
                attributeValue.InnerText = attribute.Value;
                attributeElement.AppendChild(attributeValue);
            }

            // Add AuthenticationStatement
            var authenticationStatement = document.CreateElement("saml", "AuthenticationStatement", "urn:oasis:names:tc:SAML:1.0:assertion");
            authenticationStatement.SetAttribute("AuthenticationMethod", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport");
            authenticationStatement.SetAttribute("AuthenticationInstant", DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ"));
            assertion.AppendChild(authenticationStatement);

            // Add Subject to AuthenticationStatement
            var authSubject = document.CreateElement("saml", "Subject", "urn:oasis:names:tc:SAML:1.0:assertion");
            authenticationStatement.AppendChild(authSubject);

            var authNameIdentifier = document.CreateElement("saml", "NameIdentifier", "urn:oasis:names:tc:SAML:1.0:assertion");
            authNameIdentifier.SetAttribute("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified");
            authNameIdentifier.InnerText = nameIdentifierValue;
            authSubject.AppendChild(authNameIdentifier);

            var authSubjectConfirmation = document.CreateElement("saml", "SubjectConfirmation", "urn:oasis:names:tc:SAML:1.0:assertion");
            authSubject.AppendChild(authSubjectConfirmation);

            var authConfirmationMethod = document.CreateElement("saml", "ConfirmationMethod", "urn:oasis:names:tc:SAML:1.0:assertion");
            authConfirmationMethod.InnerText = "urn:oasis:names:tc:SAML:1.0:cm:bearer";
            authSubjectConfirmation.AppendChild(authConfirmationMethod);

            // Load certificate
            if (pfxPassword != null)
            {
                certificate = new X509Certificate2(pfxFilePath, pfxPassword, X509KeyStorageFlags.Exportable);
            }
            else
            {
                certificate = new X509Certificate2(pfxFilePath, "", X509KeyStorageFlags.Exportable);
            }

            // Ensure we have access to the private key
            if (!certificate.HasPrivateKey)
            {
                throw new Exception("Certificate does not contain a private key required for signing");
            }

            // FIXED: Use CustomSignedXml and proper signing approach
            var signedXml = new CustomSignedXml(document, assertionId);
            signedXml.SigningKey = certificate.PrivateKey;
            signedXml.SignedInfo.CanonicalizationMethod = SignedXml.XmlDsigExcC14NTransformUrl;
            signedXml.SignedInfo.SignatureMethod = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";

            // Create reference to the assertion using AssertionID
            var reference = new Reference("#" + assertionId);
            reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());
            reference.AddTransform(new XmlDsigExcC14NTransform());
            reference.DigestMethod = "http://www.w3.org/2001/04/xmlenc#sha256";

            signedXml.AddReference(reference);

            // Include the public key of the certificate in the assertion
            signedXml.KeyInfo = new KeyInfo();
            signedXml.KeyInfo.AddClause(new KeyInfoX509Data(certificate, X509IncludeOption.EndCertOnly));

            // FIXED: Compute signature with proper error handling
            try
            {
                signedXml.ComputeSignature();
            }
            catch (Exception ex)
            {
                throw new Exception($"Failed to compute signature: {ex.Message}", ex);
            }

            // Get the signature element and add it to the assertion
            var signatureElement = signedXml.GetXml();
            assertion.AppendChild(signatureElement);

            // Add remaining WS-Trust elements
            var tokenType = document.CreateElement("t", "TokenType", "http://schemas.xmlsoap.org/ws/2005/02/trust");
            tokenType.InnerText = "urn:oasis:names:tc:SAML:1.0:assertion";
            response.AppendChild(tokenType);

            var requestType = document.CreateElement("t", "RequestType", "http://schemas.xmlsoap.org/ws/2005/02/trust");
            requestType.InnerText = "http://schemas.xmlsoap.org/ws/2005/02/trust/Issue";
            response.AppendChild(requestType);

            var keyType = document.CreateElement("t", "KeyType", "http://schemas.xmlsoap.org/ws/2005/02/trust");
            keyType.InnerText = "http://schemas.xmlsoap.org/ws/2005/05/identity/NoProofKey";
            response.AppendChild(keyType);

            var xmlBytes = Encoding.UTF8.GetBytes(document.OuterXml);
            var xmlString = Encoding.UTF8.GetString(xmlBytes);

            // Fix the insidecorporatenetwork attribute by replacing it with the correct format
            var wrongPattern = @"<saml:Attribute\s+AttributeName=""insidecorporatenetwork""\s+AttributeNamespace=""http://schemas\.microsoft\.com/ws/2012/01"">\s*<saml:AttributeValue>false</saml:AttributeValue>\s*</saml:Attribute>";
            var correctReplacement = @"<saml:Attribute AttributeName=""insidecorporatenetwork"" AttributeNamespace=""http://schemas.microsoft.com/ws/2012/01"" a:OriginalIssuer=""CLIENT CONTEXT"" xmlns:a=""http://schemas.xmlsoap.org/ws/2009/09/identity/claims""><saml:AttributeValue b:type=""tn:boolean"" xmlns:tn=""http://www.w3.org/2001/XMLSchema"" xmlns:b=""http://www.w3.org/2001/XMLSchema-instance"">false</saml:AttributeValue></saml:Attribute>";

            xmlString = System.Text.RegularExpressions.Regex.Replace(xmlString, wrongPattern, correctReplacement, RegexOptions.IgnoreCase | RegexOptions.Multiline);

            // Direct URL encoding of XML (no Base64 first) to match the target format
            var urlEncodedResponse = HttpUtility.UrlEncode(xmlString);
            var wsFederationResponse = Regex.Replace(urlEncodedResponse, @"%[a-f\d]{2}", m => m.Value.ToUpper());

            // Add the wctx parameter to match the expected WS-Federation format
            var wctxValue = "LoginOptions%3D3%26estsredirect%3D2%26estsrequest%3DrQQIARAAjZM9jNt0GMbzcZfeRUCvBVUwIJ0EQgjh5G87_shJlcjZ-fAlts-JE8dG4pQ4dmzH9t9nO3bikYnxEFM7oRtvqjrwNXUCdCwVY9VKiLEDKiw9dSItCwsS0vu-eh-9z7v9nvI1ukJUQAV8VMQq4OD9GkUStRoxRXBMJ5FafQoQGjdIBJ3V8c0Jo0h9Et4s740-e_fH519-Ld756cXpp38Kv17kP7DiOIgOqtU0TSuerYcwgmaMk0RFh17Vnfgz258n2Hf5_MN8_m5h2_CR4eCiEJE4TVNUHeB1fNMkDcgKL2suz7YsVRnGojzH1AEAvKISPXmR8jIXi8rIUR2VUB0O15RmKsp9W2MlXGjzsSo3gGoDoLGLjd9ytY1fkFuOoLQsPuNQgW1kjwrXxcYytrCXA4Z2ZvxV2DVh6J0EMIrvFh8U2N5RIDuaqc4DTqnrK8cdSXRrPbN7IYVKjCgsZQ04gBZ5ewoPvbE6c-NM6zIjfLhaEUEmDNqmbBmxP8L5joQACxtontvywqBHaGQqHU9MpB91mqjTxxeDMZ6tO5KkECRLJbILKUY_NgCeDTJm4C_N_mkyGddEVlgs18mKaFhAatAoP3dSZ4oSvjGSKQQ9HCXtsYaIWpd3VquGMp9odA9FORwJTMyjCQLU6iJl2PFhO-XqR4M4kLmWVZ8wcDScgzgJmrFQWx_NxQAQQhojCsrKNZKxGbJj1FFDiZjMEta20rbSeIocHSU8sjCtaCKxTmvYWCPuxOxa9XXXIdTTdHZRfOffOEDTtHXjFQgJdr9Y2iwe9C-LFAwM357tByE0bdfY_8-fqvhKdaBnVBqu-3vxPXft-5UQTqe2H33iwzC2UtufxeFkZoRRRXfhcvZwK_9069bOzt7227n93IdvgeLBzk55L_dSXW3lz7c3HPP3jPvfnD9mv_rl_Gr-863c5Xa1t0g7ti4NmuKYUrUOsQpIVKZbppF0yX7Q5TqePkz8npCt6dv4AXpWyp-VSpelXY49EZoyfQKelfJfXMv9sPs_E_HotTfL5aV94kJ94hrRzX-S8eD13NUb33_7-Mmdz5_90Xl6_WNrtBQUtd0OZdiPLZxj2iRhLWdOz_Kg3KlxGNMUjoUxMcXnt-_t5X7b1I3c1Y2zwt81";

            return $"{wsFederationResponse}&wctx={wctxValue}";
        }
        catch (Exception ex)
        {
            throw new Exception("Failed to generate WS-Federation response", ex);
        }
    }

    private static string GetAttributeNamespace(string attributeName)
    {
        return attributeName.ToLower() switch
        {
            "upn" => "http://schemas.xmlsoap.org/claims",
            "immutableid" => "http://schemas.microsoft.com/LiveID/Federation/2008/05",
            "insidecorporatenetwork" => "http://schemas.microsoft.com/ws/2012/01",
            "authnmethodsreferences" => "http://schemas.microsoft.com/claims",
            "email" => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims",
            "name" => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims",
            "givenname" => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims",
            "surname" => "http://schemas.xmlsoap.org/ws/2005/05/identity/claims",
            _ => "http://schemas.xmlsoap.org/claims"
        };
    }
}