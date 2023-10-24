using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using static BTCPayServer.NTag424.Helpers;

namespace BTCPayServer.NTag424;

/// <summary>
/// Implement deterministic key derivation. <see cref="https://github.com/boltcard/boltcard/blob/main/docs/DETERMINISTIC.md"/>
/// </summary>
/// <param name="AESKey"></param>
public record IssuerKey(AESKey AESKey)
{
    public static IssuerKey Random() => new IssuerKey(AESKey.Random());
    public IssuerKey(ReadOnlySpan<byte> bytes) : this(new AESKey(bytes))
    {
            
    }
    public AESKey DeriveEncryptionKey()
    {        
        return AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x77 }));
    }

    /// <summary>
    /// Get the ID from the UID
    /// </summary>
    /// <param name="uid">The UID</param>
    /// <returns>The ID used to fetch CardKey from database</returns>
    public byte[] GetId(byte[] uid)
    {
        Helpers.ValidateUID(uid);
        return AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x7b },
            uid)).ToBytes().ToArray();
    }

    /// <summary>
    /// Decrypt the PICCData from the BoltCard and check the checksum.
    /// </summary>
    /// <param name="uri">The url with p= and c= parameters</param
    /// <returns>The PICCData if the checksum passed verification or null.</returns>
    public BoltcardPICCData? TryDecrypt(Uri? uri)
    {
        return BoltcardPICCData.TryDecrypt(DeriveEncryptionKey(), uri);
    }

    /// <summary>
    /// Decrypt the PICCData from the Boltcard and check the checksum.
    /// </summary>
    /// <param name="encryptionKey">The encryption key (K1)</param>
    /// <param name="p">p= encrypted PICCData parameter</param>
    /// <returns>The PICCData if the checksum passed verification or null.</returns>
    public BoltcardPICCData? TryDecrypt(string p)
    {
        return BoltcardPICCData.TryDecrypt(DeriveEncryptionKey(), p);
    }
}
