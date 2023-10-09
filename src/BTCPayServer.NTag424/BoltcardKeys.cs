using System.Security.Cryptography.X509Certificates;

namespace BTCPayServer.NTag424;

/// <summary>
/// The keys saved into the BoltCard
/// </summary>
/// <param name="IssuerKey">The key of the issuer, used to change key settings</param>
/// <param name="EncryptionKey">The key used to encrypt PICCData (p=)</param>
/// <param name="AuthenticationKey">The key used to authenticated PICCData (c=)</param>
/// <param name="K3">Unused, shouldn't be predictable</param>
/// <param name="K4">Unused, shouldn't be predictable</param>
public record BoltcardKeys(
    AESKey IssuerKey,
    AESKey EncryptionKey,
    AESKey AuthenticationKey,
    AESKey K3,
    AESKey K4)
{
    public static BoltcardKeys Default = new BoltcardKeys(AESKey.Default, AESKey.Default, AESKey.Default, AESKey.Default, AESKey.Default);
    public BoltcardKeys() : this (AESKey.Default, AESKey.Default, AESKey.Default, AESKey.Default, AESKey.Default)
    {
    }
}
