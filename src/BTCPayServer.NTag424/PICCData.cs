
using System;
using System.Runtime.Loader;
using System.Security;

namespace BTCPayServer.NTag424;

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
    /// It assumes the authentication key has been derived from the encryption key. (ie. CMacDerive(encryptionKey, '2d003f78' + uid))
    /// </summary>
    /// <param name="encryptionKey">The encryption key for p</param>
    /// <param name="p">The p= parameter from the lnurlw (encrypted PICCData)</param>
    /// <param name="c">THe c= parameter from the lnurlw (checksum)</param>
    /// <param name="payload">Optional payload committed by c</param>
    /// <returns>The PICCData if the checksum passed verification.</returns>
    /// <exception cref="SecurityException">Invalid PICCData or checksum</exception>
    public static PICCData BoltcardDecrypt(AESKey encryptionKey, string p, string c, byte[]? payload = null)
    {
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
        if (piccData.Uid is null)
            throw new SecurityException("No UID found in the PICCData");

        var authenticationKey = encryptionKey.DeriveAuthenticationKey(piccData.Uid);
        if (!authenticationKey.CheckSunMac(c, piccData, payload))
            throw new SecurityException("Incorrect checksum for the PICCDAta");
        return piccData;
    }
}
