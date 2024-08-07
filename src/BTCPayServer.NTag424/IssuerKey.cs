using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Security.Cryptography;
using System.Text.RegularExpressions;
using static BTCPayServer.NTag424.Helpers;
using static BTCPayServer.NTag424.Ntag424;

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

    public CardKey CreateCardKey(byte[] uid, int version)
    {
        return CreateCardKey(uid, version, null);
    }
    public CardKey CreateCardKey(byte[] uid, int version, byte[]? additionalData)
    {
        Helpers.ValidateUID(uid);
        if (version < 0)
            throw new ArgumentOutOfRangeException(nameof(version));
        additionalData ??= Array.Empty<byte>();
        var k = AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x75 },
            uid,
            Helpers.UIntToBytesLE((uint)version),
            additionalData));
        return new CardKey(k);
    }

    public AESKey DeriveEncryptionKey()
    {        
        return AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x77 }));
    }

    public bool CheckSunMac([NotNullWhen(true)] Uri? uri, BoltcardPICCData piccData, int version, byte[]? payload = null)
    {
        if (!PICCData.ExtractPC(uri, out _, out var c))
            return false;
        return CheckSunMac(c, piccData, version, payload);
    }
    public bool CheckSunMac([NotNullWhen(true)] string? c, BoltcardPICCData piccData, int version, byte[]? payload = null)
    {
        var cardKey = CreateCardKey(piccData.Uid, version);
        return cardKey.CheckSunMac(c, piccData, payload);
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
    /// Decrypt the PICCData from the BoltCard. (The checksum isn't verified)
    /// </summary>
    /// <param name="uri">The url with p= and c= parameters</param
    /// <returns>The PICCData if it has been decrypted.</returns>
    public BoltcardPICCData? TryDecrypt(Uri? uri)
    {
        return BoltcardPICCData.TryDecrypt(DeriveEncryptionKey(), uri);
    }

    /// <summary>
    /// Decrypt the PICCData from the BoltCard. (The checksum isn't verified)
    /// </summary>
    /// <param name="p">p= encrypted PICCData parameter</param>
    /// <returns>The PICCData if it has been decrypted.</returns>
    public BoltcardPICCData? TryDecrypt(string p)
    {
        return BoltcardPICCData.TryDecrypt(DeriveEncryptionKey(), p);
    }
}
