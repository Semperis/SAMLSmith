// This component is a translation into C# from the original Python tool ADFSpoof
// created by Doug Bienstock while at Mandiant FireEye, licensed under
// Apache License 2.0. Original source: https://github.com/mandiant/ADFSpoof


using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Linq;
using System.Security.Cryptography.X509Certificates;

namespace SAMLSmith
{
    public class EncryptedPFXDecryptor
    {
        private byte[] _rawData;
        private byte[] _decryptionKey;
        private byte[] _encryptionKey;
        private byte[] _macKey;
        private byte[] _nonce;
        private byte[] _iv;
        private byte[] _ciphertext;
        private byte[] _mac;
        private string _encryptionOid;
        private string _macOid;
        private bool _debug;

        public EncryptedPFXDecryptor(string tksPath, string dmkeyPath, bool debug = false)
        {
            _debug = debug;
            _rawData = File.ReadAllBytes(tksPath);
            _decryptionKey = File.ReadAllBytes(dmkeyPath);

            DecodePFX();
        }

        public byte[] DecryptPFX()
        {
            DeriveKeys();
            VerifyMAC();

            using (var aes = Aes.Create())
            {
                aes.Key = _encryptionKey;
                aes.IV = _iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                using (var decryptor = aes.CreateDecryptor())
                {
                    return decryptor.TransformFinalBlock(_ciphertext, 0, _ciphertext.Length);
                }
            }
        }

        private void DecodePFX()
        {
            int offset = 0;

            // Read version (should be 1)
            uint version = BitConverter.ToUInt32(_rawData.Skip(offset).Take(4).Reverse().ToArray(), 0);
            offset += 4;

            if (version != 1)
                throw new InvalidOperationException("Invalid version. Expected 1.");

            // Read method (should be 0 for EncryptThenMAC)
            uint method = BitConverter.ToUInt32(_rawData.Skip(offset).Take(4).Reverse().ToArray(), 0);
            offset += 4;

            if (method != 0)
                throw new InvalidOperationException("Only EncryptThenMAC is supported.");

            // Decode GroupKey GUID
            var guidBytes = DecodeOctetString(_rawData, ref offset);
            var guid = DecodeGuid(guidBytes);

            // Decode algorithm OIDs
            DecodeAuthEncrypt(_rawData, ref offset);

            // Decode nonce
            _nonce = DecodeOctetString(_rawData, ref offset);

            // Decode IV
            _iv = DecodeOctetString(_rawData, ref offset);

            // Decode MAC length
            int macLength = DecodeLength(_rawData, ref offset);

            // Decode ciphertext length
            int ciphertextLength = DecodeLength(_rawData, ref offset);

            // Extract ciphertext and MAC
            _ciphertext = _rawData.Skip(offset).Take(ciphertextLength - macLength).ToArray();
            _mac = _rawData.Skip(offset + ciphertextLength - macLength).Take(macLength).ToArray();

            if (_debug)
            {
                Console.WriteLine($"Version: {version}");
                Console.WriteLine($"Method: {method}");
                Console.WriteLine($"GUID: {guid}");
                Console.WriteLine($"Nonce: {BitConverter.ToString(_nonce)}");
                Console.WriteLine($"IV: {BitConverter.ToString(_iv)}");
                Console.WriteLine($"MAC Length: {macLength}");
                Console.WriteLine($"Ciphertext Length: {ciphertextLength}");
            }
        }

        private byte[] DecodeOctetString(byte[] data, ref int offset)
        {
            // Simple ASN.1 OCTET STRING decoder
            if (data[offset] != 0x04) // OCTET STRING tag
                throw new InvalidOperationException("Expected OCTET STRING tag");

            offset++;
            int length = DecodeLength(data, ref offset);
            var result = data.Skip(offset).Take(length).ToArray();
            offset += length;
            return result;
        }

        private int DecodeLength(byte[] data, ref int offset)
        {
            int length = data[offset++];

            if (length < 0x80)
            {
                return length;
            }
            else
            {
                int lengthBytes = length & 0x7F;
                length = 0;

                for (int i = 0; i < lengthBytes; i++)
                {
                    length = (length << 8) | data[offset++];
                }

                return length;
            }
        }

        private Guid DecodeGuid(byte[] guidBytes)
        {
            if (guidBytes.Length != 16)
                throw new ArgumentException("GUID must be 16 bytes");

            // Convert to .NET GUID format
            var guidData = new byte[16];

            // First 4 bytes (little endian)
            guidData[0] = guidBytes[3];
            guidData[1] = guidBytes[2];
            guidData[2] = guidBytes[1];
            guidData[3] = guidBytes[0];

            // Next 2 bytes (little endian)
            guidData[4] = guidBytes[5];
            guidData[5] = guidBytes[4];

            // Next 2 bytes (little endian)
            guidData[6] = guidBytes[7];
            guidData[7] = guidBytes[6];

            // Last 8 bytes (big endian)
            Array.Copy(guidBytes, 8, guidData, 8, 8);

            return new Guid(guidData);
        }

        private void DecodeAuthEncrypt(byte[] data, ref int offset)
        {
            // Skip the main OID
            SkipOid(data, ref offset);

            // Read MAC OID
            _macOid = ReadOid(data, ref offset);

            // Read Encryption OID
            _encryptionOid = ReadOid(data, ref offset);

            if (_debug)
            {
                Console.WriteLine($"MAC OID: {_macOid}");
                Console.WriteLine($"Encryption OID: {_encryptionOid}");
            }
        }

        private void SkipOid(byte[] data, ref int offset)
        {
            if (data[offset] != 0x06) // OID tag
                throw new InvalidOperationException("Expected OID tag");

            offset++;
            int length = data[offset++];
            offset += length;
        }

        private string ReadOid(byte[] data, ref int offset)
        {
            if (data[offset] != 0x06) // OID tag
                throw new InvalidOperationException("Expected OID tag");

            offset++;
            int length = data[offset++];
            var oidBytes = data.Skip(offset).Take(length).ToArray();
            offset += length;

            return DecodeOidBytes(oidBytes);
        }

        private string DecodeOidBytes(byte[] oidBytes)
        {
            var result = new StringBuilder();

            if (oidBytes.Length == 0)
                return "";

            // First byte encodes first two subidentifiers
            int firstByte = oidBytes[0];
            result.Append(firstByte / 40);
            result.Append(".");
            result.Append(firstByte % 40);

            // Process remaining bytes
            int i = 1;
            while (i < oidBytes.Length)
            {
                int value = 0;
                while (i < oidBytes.Length && (oidBytes[i] & 0x80) != 0)
                {
                    value = (value << 7) | (oidBytes[i] & 0x7F);
                    i++;
                }

                if (i < oidBytes.Length)
                {
                    value = (value << 7) | oidBytes[i];
                    i++;
                }

                result.Append(".");
                result.Append(value);
            }

            return result.ToString();
        }

        private void DeriveKeys()
        {
            // Prepare label and context for KBKDF - use DER encoded OIDs
            var encOidBytes = EncodeDerOid(_encryptionOid);
            var macOidBytes = EncodeDerOid(_macOid);
            var label = encOidBytes.Concat(macOidBytes).ToArray();
            var context = _nonce;

            if (_debug)
            {
                Console.WriteLine($"Encryption OID DER: {BitConverter.ToString(encOidBytes)}");
                Console.WriteLine($"MAC OID DER: {BitConverter.ToString(macOidBytes)}");
                Console.WriteLine($"Label: {BitConverter.ToString(label)}");
                Console.WriteLine($"Label hex (no dashes): {BitConverter.ToString(label).Replace("-", "").ToLower()}");
                Console.WriteLine($"Context: {BitConverter.ToString(context)}");
                Console.WriteLine($"Decryption key: {BitConverter.ToString(_decryptionKey)}");
            }

            // Derive keys using KBKDF in Counter Mode
            var derivedKey = KBKDF_HMAC_SHA256(
                _decryptionKey,
                label,
                context,
                48, // 16 bytes for AES-128 + 32 bytes for HMAC-SHA256
                4,  // rlen
                4   // llen
            );

            _encryptionKey = derivedKey.Take(16).ToArray();
            _macKey = derivedKey.Skip(16).ToArray();

            if (_debug)
            {
                Console.WriteLine($"Derived Key: {BitConverter.ToString(derivedKey)}");
                Console.WriteLine($"Derived Key hex (no dashes): {BitConverter.ToString(derivedKey).Replace("-", "").ToLower()}");
                Console.WriteLine($"Encryption Key: {BitConverter.ToString(_encryptionKey)}");
                Console.WriteLine($"MAC Key: {BitConverter.ToString(_macKey)}");
            }
        }

        private byte[] EncodeDerOid(string oid)
        {
            var parts = oid.Split('.');
            var encodedBytes = new List<byte>();

            // First two parts are encoded in first byte
            int firstByte = int.Parse(parts[0]) * 40 + int.Parse(parts[1]);
            encodedBytes.Add((byte)firstByte);

            // Encode remaining parts
            for (int i = 2; i < parts.Length; i++)
            {
                int value = int.Parse(parts[i]);
                var valueBytes = new List<byte>();

                if (value == 0)
                {
                    valueBytes.Add(0);
                }
                else
                {
                    while (value > 0)
                    {
                        valueBytes.Insert(0, (byte)(value & 0x7F));
                        value >>= 7;
                    }

                    // Set continuation bit on all bytes except the last
                    for (int j = 0; j < valueBytes.Count - 1; j++)
                    {
                        valueBytes[j] |= 0x80;
                    }
                }

                encodedBytes.AddRange(valueBytes);
            }

            // Create DER encoded OID: tag (0x06) + length + encoded bytes
            var result = new List<byte>();
            result.Add(0x06); // OID tag
            result.Add((byte)encodedBytes.Count); // Length
            result.AddRange(encodedBytes); // Encoded OID

            return result.ToArray();
        }

        private byte[] KBKDF_HMAC_SHA256(byte[] key, byte[] label, byte[] context, int length, int rlen, int llen)
        {
            int rounds = (int)Math.Ceiling((double)length / 32.0); // SHA256 produces 32 bytes
            var output = new List<byte>();

            for (int i = 1; i <= rounds; i++)
            {
                using (var hmac = new HMACSHA256(key))
                {
                    // Counter (big-endian, rlen bytes) - this goes first (BeforeFixed)
                    var counter = BitConverter.GetBytes(i);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(counter);

                    // Adjust counter to rlen bytes
                    var counterBytes = new byte[rlen];
                    Array.Copy(counter, Math.Max(0, counter.Length - rlen),
                              counterBytes, Math.Max(0, rlen - counter.Length),
                              Math.Min(counter.Length, rlen));

                    // Fixed input: label + 0x00 + context + L
                    var fixedInput = new List<byte>();
                    fixedInput.AddRange(label);
                    fixedInput.Add(0x00);
                    fixedInput.AddRange(context);

                    // Length L (in bytes, not bits!, big-endian, llen bytes)
                    var lengthInBytes = length;
                    var lengthBytes = BitConverter.GetBytes(lengthInBytes);
                    if (BitConverter.IsLittleEndian)
                        Array.Reverse(lengthBytes);

                    // Adjust length to llen bytes
                    var lengthBytesAdjusted = new byte[llen];
                    Array.Copy(lengthBytes, Math.Max(0, lengthBytes.Length - llen),
                              lengthBytesAdjusted, Math.Max(0, llen - lengthBytes.Length),
                              Math.Min(lengthBytes.Length, llen));

                    fixedInput.AddRange(lengthBytesAdjusted);

                    // HMAC input: counter + fixed input (BeforeFixed mode)
                    var hmacInput = new List<byte>();
                    hmacInput.AddRange(counterBytes);
                    hmacInput.AddRange(fixedInput);

                    if (_debug && i == 1)
                    {
                        Console.WriteLine($"  Counter: {BitConverter.ToString(counterBytes)}");
                        Console.WriteLine($"  Label: {BitConverter.ToString(label)}");
                        Console.WriteLine($"  Context: {BitConverter.ToString(context)}");
                        Console.WriteLine($"  Length (bytes): {lengthInBytes}");
                        Console.WriteLine($"  Length bytes: {BitConverter.ToString(lengthBytesAdjusted)}");
                        Console.WriteLine($"  Fixed input: {BitConverter.ToString(fixedInput.ToArray())}");
                        Console.WriteLine($"  HMAC input: {BitConverter.ToString(hmacInput.ToArray())}");
                        Console.WriteLine($"  HMAC input hex: {BitConverter.ToString(hmacInput.ToArray()).Replace("-", "").ToLower()}");
                    }

                    var hash = hmac.ComputeHash(hmacInput.ToArray());
                    output.AddRange(hash);

                    if (_debug && i == 1)
                    {
                        Console.WriteLine($"  Hash: {BitConverter.ToString(hash)}");
                    }
                }
            }

            // Return only the requested number of bytes
            var result = new byte[length];
            Array.Copy(output.ToArray(), result, length);
            return result;
        }

        private void VerifyMAC()
        {
            using (var hmac = new HMACSHA256(_macKey))
            {
                var dataToVerify = _iv.Concat(_ciphertext).ToArray();
                var calculatedMac = hmac.ComputeHash(dataToVerify);

                if (!calculatedMac.SequenceEqual(_mac))
                {
                    throw new InvalidOperationException("MAC verification failed");
                }

                if (_debug)
                {
                    Console.WriteLine($"MAC verification successful");
                    Console.WriteLine($"Expected MAC: {BitConverter.ToString(_mac)}");
                    Console.WriteLine($"Calculated MAC: {BitConverter.ToString(calculatedMac)}");
                }
            }
        }

        public static void SavePFX(byte[] pfxData, string outputPath)
        {
            File.WriteAllBytes(outputPath, pfxData);
        }
    }
    }
