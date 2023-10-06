using System.Security.Cryptography.X509Certificates;

namespace BTCPayServer.NTag424;
public record BoltcardKeys(AESKey IssuerKey, AESKey EncryptionKey, AESKey AuthenticationKey)
{
    public static BoltcardKeys Default = new BoltcardKeys(AESKey.Default, AESKey.Default, AESKey.Default);
    public BoltcardKeys() : this (AESKey.Default, AESKey.Default, AESKey.Default)
    {
    }
}
