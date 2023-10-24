using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BTCPayServer.NTag424;
public record CardKey(AESKey AESKey)
{
    public CardKey(byte[] bytes) : this(new AESKey(bytes))
    {
        
    }
    public AESKey DeriveAuthenticationKey(byte[] uid)
    {
        Helpers.ValidateUID(uid);
        return AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x78 },
            uid));
    }
    public BoltcardKeys DeriveBoltcardKeys(IssuerKey issuerKey, byte[] uid)
    {
        return DeriveBoltcardKeys(issuerKey.DeriveEncryptionKey(), uid);
    }
    public BoltcardKeys DeriveBoltcardKeys(AESKey encryptionKey, byte[] uid)
    {
        Helpers.ValidateUID(uid);
        var appMasterKey = AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x76 },
            uid));
        var authKey = DeriveAuthenticationKey(uid);
        var k1 = AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x79 },
            uid));
        var k2 = AESKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x7a },
            uid));

        return new BoltcardKeys(appMasterKey, encryptionKey, authKey, k1, k2);
    }

    public bool CheckSunMac([NotNullWhen(true)] Uri? uri, BoltcardPICCData piccData)
    {
        if (!PICCData.ExtractPC(uri, out _, out var c))
            return false;
        return this.DeriveAuthenticationKey(piccData.Uid).CheckSunMac(c, piccData);
    }
    public bool CheckSunMac([NotNullWhen(true)] string? c, BoltcardPICCData piccData)
    {
        return this.DeriveAuthenticationKey(piccData.Uid).CheckSunMac(c, piccData);
    }
}
