
using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Runtime.Loader;
using System.Security;
using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace BTCPayServer.NTag424;

public record BoltcardPICCData : PICCData
{
    public new byte[] Uid { get; }
    public new int Counter { get; }
    public BoltcardPICCData(byte[] Uid, int Counter): base(Uid, Counter)
    {
        this.Uid = Uid;
        this.Counter = Counter;
    }
    public BoltcardPICCData(PICCData piccData) : this(piccData.Uid!, piccData.Counter!.Value)
    {
    }



    /// <summary>
    /// Decrypt the PICCData from the BoltCard and check the checksum.
    /// </summary>
    /// <param name="encryptionKey">The encryption key (K1)</param>
    /// <param name="uri">The url with p= and c= parameters</param
    /// <param name="payload">Optional payload committed by c</param>
    /// <returns>The PICCData if the checksum passed verification or null.</returns>
    public static BoltcardPICCData? TryDecrypt(AESKey encryptionKey, Uri? uri)
    {
        if (!ExtractPC(uri, out var p, out var c))
            return null;

        return TryDecrypt(encryptionKey, p);
    }

    // PICCData for boltcard starts with 0xc7, and end with 5 bytes of 0
    static bool ValidateBoltcardPICCData(byte[] piccData)
    {
        if (piccData is null || piccData.Length != 16)
            return false;
        return piccData[0] == 0xc7;
    }

    /// <summary>
    /// Decrypt the PICCData from the Boltcard and check the checksum.
    /// </summary>
    /// <param name="encryptionKey">The encryption key (K1)</param>
    /// <param name="p">p= encrypted PICCData parameter</param>
    /// <param name="c">c= checksum parameter</param>
    /// <returns>The PICCData if the checksum passed verification or null.</returns>
    public static BoltcardPICCData? TryDecrypt(AESKey encryptionKey, string p)
    {
        if (!ValidateP(p))
            return null;
        var bytes = encryptionKey.Decrypt(p[0..32].HexToBytes());
        if (!ValidateBoltcardPICCData(bytes))
            return null;
        return new BoltcardPICCData(PICCData.Create(bytes));
    }
}
public record PICCData(byte[]? Uid, int? Counter)
{
    public static PICCData Create(ReadOnlySpan<byte> data)
    {
        bool hasUid = (data[0] & 0b1000_0000) != 0;
        bool hasCounter = (data[0] & 0b0100_0000) != 0;
        if (hasUid && ((data[0] & 0b0000_0111) != 0b0000_0111))
            throw new InvalidOperationException("Invalid PICCData");
        int i = 1;
        byte[]? uid = null;
        int? counter = null;
        if (hasUid)
        {
            uid = data[i..(i + 7)].ToArray();
            i += 7;
        }
        if (hasCounter)
        {
            counter = data[i] | data[i + 1] << 8 | data[i + 2] << 16;
        }
        return new PICCData(uid, counter);
    }

    internal static bool ExtractPC(Uri? uri, [MaybeNullWhen(false)] out string p, [MaybeNullWhen(false)] out string c)
    {
        p = null;
        c = null;
        if (uri is null)
            return false;
        var queryStringIdx = uri.AbsoluteUri.IndexOf('?');
        if (queryStringIdx == -1)
            return false;
        var queryString = uri.AbsoluteUri.Substring(queryStringIdx);
        var pm = Regex.Match(queryString, "p=([a-f0-9A-F]{32})");
        var cm = Regex.Match(queryString, "c=([a-f0-9A-F]{16})");
        if (!pm.Success || !cm.Success)
            return false;
        p = pm.Groups[1].Value;
        c = cm.Groups[1].Value;
        return true;
    }

    /// <summary>
    /// Decrypt the PICCData from the Boltcard and check the checksum.
    /// </summary>
    /// <param name="encryptionKey">The encryption key (K1)</param>
    /// <param name="authenticationKey">The authentication key (K2)</param>
    /// <param name="uri">The url with p= and c= parameters</param
    /// <param name="payload">Optional payload committed by c</param>
    /// <returns>The PICCData if the checksum passed verification or null.</returns>
    public static PICCData? TryBoltcardDecryptCheck(AESKey encryptionKey, AESKey authenticationKey, Uri? uri, byte[]? payload = null)
    {
        if (!ExtractPC(uri, out var p, out var c))
            return null;
        return TryBoltcardDecryptCheck(encryptionKey, authenticationKey, p, c, payload);
    }
    internal static bool ValidateP([NotNullWhen(true)] string? p) => p is not null && Regex.IsMatch(p, "^[a-f0-9A-F]{32}");
    internal static bool ValidateC([NotNullWhen(true)] string? c) => c is not null && Regex.IsMatch(c, "^[a-f0-9A-F]{16}");

    /// <summary>
    /// Decrypt the PICCData from the Boltcard and check the checksum.
    /// </summary>
    /// <param name="encryptionKey">The encryption key (K1)</param>
    /// <param name="authenticationKey">The authentication key (K2)</param>
    /// <param name="p">The p= parameter from the lnurlw (encrypted PICCData)</param>
    /// <param name="c">THe c= parameter from the lnurlw (checksum)</param>
    /// <param name="payload">Optional payload committed by c</param>
    /// <returns>The PICCData if the checksum passed verification or null.</returns>
    public static PICCData? TryBoltcardDecryptCheck(AESKey encryptionKey, AESKey authenticationKey, string p, string c, byte[]? payload = null)
    {
        if (!ValidateP(p) || !ValidateC(c))
            return null;

        var bytes = encryptionKey.Decrypt(p[0..32].HexToBytes());
        PICCData piccData;
        try
        {
            piccData = PICCData.Create(bytes);
        }
        catch
        {
            throw new SecurityException("Invalid PICCData");
        }
        if (!authenticationKey.CheckSunMac(c, piccData, payload))
            return null;
        return piccData;
    }
}
