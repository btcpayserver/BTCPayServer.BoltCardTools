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
    public IssuerKey(ReadOnlySpan<byte> bytes) : this(new AESKey(bytes))
    {
            
    }
    public static byte[] RandomNonce()
    {
        var nonce = new byte[16];
        RandomNumberGenerator.Fill(nonce);
        return nonce;
    }
    public AESKey DeriveEncryptionKey()
    {        
        return AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x77 }));
    }
    private void Validate(byte[] uid)
    {
        ArgumentNullException.ThrowIfNull(uid);
        if (uid.Length != 7)
            throw new ArgumentException("uid should be 7 bytes", nameof(uid));
    }
    private void Validate(byte[] uid, byte[] nonce)
    {
        Validate(uid);
        ArgumentNullException.ThrowIfNull(nonce);
        if (nonce.Length != 16)
            throw new ArgumentException("nonce should be 16 bytes", nameof(nonce));
    }
    public AESKey DeriveAuthenticationKey(byte[] uid, byte[] nonce)
    {
        Validate(uid, nonce);
        return AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x78 },
            uid,
            nonce));
    }

    public BoltcardKeys DeriveBoltcardKeys(byte[] uid, byte[] nonce)
    {
        Validate(uid, nonce);
        var appMasterKey = AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x76 },
            uid,
            nonce));
        var encryptionKey = DeriveEncryptionKey();
        var authKey = DeriveAuthenticationKey(uid, nonce);
        var k1 = AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x79 },
            uid,
            nonce));
        var k2 = AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x7a },
            uid,
            nonce));

        return new BoltcardKeys(appMasterKey, encryptionKey, authKey, k1, k2);
    }

    /// <summary>
    /// Get the ID from the UID
    /// </summary>
    /// <param name="uid">The UID</param>
    /// <returns>The ID</returns>
    public byte[] GetId(byte[] uid)
    {
        Validate(uid);
        return AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x7b },
            uid)).ToBytes().ToArray();
    }

    /// <summary>
    /// Decrypt the PICCData from the BoltCard and check the checksum.
    /// </summary>
    /// <param name="uri">The url with p= and c= parameters</param
    /// <param name="payload">Optional payload committed by c</param>
    /// <returns>The PICCData if the checksum passed verification or null.</returns>
    public BoltcardPICCData? TryDecrypt(Uri? uri, byte[]? payload = null)
    {
        return BoltcardPICCData.TryDecrypt(DeriveEncryptionKey(), uri, payload);
    }

    /// <summary>
    /// Decrypt the PICCData from the Boltcard and check the checksum.
    /// </summary>
    /// <param name="encryptionKey">The encryption key (K1)</param>
    /// <param name="p">p= encrypted PICCData parameter</param>
    /// <param name="c">c= checksum parameter</param>
    /// <param name="payload">Optional payload committed by c</param>
    /// <returns>The PICCData if the checksum passed verification or null.</returns>
    public BoltcardPICCData? TryDecrypt(string p, string c, byte[]? payload = null)
    {
        return BoltcardPICCData.TryDecrypt(DeriveEncryptionKey(), p, c, payload);
    }

    public bool CheckSunMac([NotNullWhen(true)] Uri? uri, BoltcardPICCData piccData, byte[] nonce)
    {
        if (!PICCData.ExtractPC(uri, out _, out var c))
            return false;
        return this.DeriveAuthenticationKey(piccData.Uid, nonce).CheckSunMac(c, piccData);
    }
    public bool CheckSunMac([NotNullWhen(true)] string? c, BoltcardPICCData piccData, byte[] nonce)
    {
        return this.DeriveAuthenticationKey(piccData.Uid, nonce).CheckSunMac(c, piccData);
    }
}
