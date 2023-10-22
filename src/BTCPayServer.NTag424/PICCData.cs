
using System;
using System.Linq;
using System.Runtime.Loader;
using System.Security;

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

    /// <summary>
    /// Decrypt the PICCData from the BoltCard and check the checksum.
    /// </summary>
    /// <param name="batchKeys">The deterministic batch keys</param>
    /// <param name="p">The p= parameter from the lnurlw (encrypted PICCData)</param>
    /// <param name="c">The c= parameter from the lnurlw (checksum)</param>
    /// <param name="payload">Optional payload committed by c</param>
    /// <returns>The PICCData if the checksum passed verification or null.</returns>
    public static BoltcardPICCData? TryDeterministicBoltcardDecrypt(DeterministicBatchKeys batchKeys, string p, string c, byte[]? payload = null)
    {
        if (!Validate(p, c))
            return null;
        var encryptionKey = batchKeys.DeriveEncryptionKey();
        var bytes = encryptionKey.Decrypt(p.HexToBytes());
        if (bytes[0] != 0xc7)
            return null;
        var piccData = new BoltcardPICCData(Create(bytes));
        var authenticationKey = batchKeys.DeriveAuthenticationKey(piccData.Uid);
        if (!authenticationKey.CheckSunMac(c, piccData, payload))
            return null;
        return new BoltcardPICCData(piccData);
    }

    private static bool Validate(string p, string c)
    {
        if (p.Length != 32 || c.Length != 16)
            return false;
        foreach(var ch in p.Concat(c))
        {
            if (Extensions.IsDigitCore(ch) == 0xff)
                return false;
        }
        return true;
    }

    /// <summary>
    /// Decrypt the PICCData from the Boltcard and check the checksum.
    /// </summary>
    /// <param name="encryptionKey">The encryption key (K1)</param>
    /// <param name="authenticationKey">The authentication key (K2)</param>
    /// <param name="p">The p= parameter from the lnurlw (encrypted PICCData)</param>
    /// <param name="c">THe c= parameter from the lnurlw (checksum)</param>
    /// <param name="payload">Optional payload committed by c</param>
    /// <returns>The PICCData if the checksum passed verification or null.</returns>
    public static PICCData? TryBoltcardDecrypt(AESKey encryptionKey, AESKey authenticationKey, string p, string c, byte[]? payload = null)
    {
        if (!Validate(p, c))
            return null;

        var bytes = encryptionKey.Decrypt(p.HexToBytes());
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
