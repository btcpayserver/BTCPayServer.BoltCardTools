using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BTCPayServer.NTag424;
public record CardKey(AESKey AESKey)
{
    public AESKey DeriveAuthenticationKey()
    {
        return AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x78 }));
    }
    public BoltcardKeys DeriveBoltcardKeys(IssuerKey issuerKey)
    {
        return DeriveBoltcardKeys(issuerKey.DeriveEncryptionKey());
    }
    public BoltcardKeys DeriveBoltcardKeys(AESKey encryptionKey)
    {
        var appMasterKey = AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x76 }));
        var authKey = DeriveAuthenticationKey();
        var k1 = AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x79 }));
        var k2 = AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x7a }));

        return new BoltcardKeys(appMasterKey, encryptionKey, authKey, k1, k2);
    }

    public bool CheckSunMac([NotNullWhen(true)] Uri? uri, BoltcardPICCData piccData, byte[]? payload = null)
    {
        if (!PICCData.ExtractPC(uri, out _, out var c))
            return false;
        return this.DeriveAuthenticationKey().CheckSunMac(c, piccData, payload);
    }
    public bool CheckSunMac([NotNullWhen(true)] string? c, BoltcardPICCData piccData, byte[]? payload = null)
    {
        return this.DeriveAuthenticationKey().CheckSunMac(c, piccData, payload);
    }
}
