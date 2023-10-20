using System;
using System.Security.Cryptography.X509Certificates;

namespace BTCPayServer.NTag424;

/// <summary>
/// The keys saved into the BoltCard
/// </summary>
/// <param name="AppMasterKey">K0: The key used to call ChangeKey</param>
/// <param name="EncryptionKey">K1: The key used to encrypt PICCData (p=)</param>
/// <param name="AuthenticationKey">K2: The key used to authenticated PICCData (c=)</param>
/// <param name="K3">Unused, shouldn't be predictable</param>
/// <param name="K4">Unused, shouldn't be predictable</param>
public record BoltcardKeys(
    AESKey AppMasterKey,
    AESKey EncryptionKey,
    AESKey AuthenticationKey,
    AESKey K3,
    AESKey K4)
{
    public static BoltcardKeys Default = new BoltcardKeys(AESKey.Default, AESKey.Default, AESKey.Default, AESKey.Default, AESKey.Default);
    public BoltcardKeys() : this (AESKey.Default, AESKey.Default, AESKey.Default, AESKey.Default, AESKey.Default)
    {
    }

    public static BoltcardKeys CreateDeterministicKeys(AESKey issuerKey, byte[] uid, uint batchId = 0)
    {
        var encryptionKey = issuerKey.DeriveEncryptionKey(batchId);
        var appMasterKey = issuerKey.DeriveAppMasterKey(uid);
        var authKey = encryptionKey.DeriveAuthenticationKey(uid);
        var k = encryptionKey.DeriveK3K4(uid);
        return new BoltcardKeys(appMasterKey, encryptionKey, authKey, k.K3, k.K4);
    }
}
