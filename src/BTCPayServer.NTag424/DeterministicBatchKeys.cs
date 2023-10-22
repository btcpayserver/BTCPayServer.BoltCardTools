using System.Linq;
using static BTCPayServer.NTag424.Helpers;

namespace BTCPayServer.NTag424;
public record DeterministicBatchKeys(AESKey IssuerKey, uint BatchId = 0)
{
    public AESKey DeriveEncryptionKey()
    {
        return IssuerKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x77 },
            UIntToBytesLE(BatchId)));
    }
    public AESKey DeriveAuthenticationKey(byte[] uid)
    {
        return IssuerKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x78 },
            UIntToBytesLE(BatchId),
            uid));
    }

    public BoltcardKeys DeriveBoltcardKeys(byte[] uid)
    {
        var appMasterKey = IssuerKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x76 },
            UIntToBytesLE(BatchId),
            uid));
        var encryptionKey = DeriveEncryptionKey();
        var authKey = DeriveAuthenticationKey(uid);
        var k1 = IssuerKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x79 },
            UIntToBytesLE(BatchId),
            uid));
        var k2 = IssuerKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x7a },
            UIntToBytesLE(BatchId),
            uid));

        return new BoltcardKeys(appMasterKey, encryptionKey, authKey, k1, k2);
    }

    /// <summary>
    /// Get the ID from the UID and the encryption key (K1)
    /// </summary>
    /// <param name="uid">The UID</param>
    /// <returns>The ID</returns>
    public byte[] GetId(byte[] uid)
    {
        return IssuerKey.Derive(Helpers.Concat(
            new byte[] { 0x2d, 0x00, 0x3f, 0x7b },
            UIntToBytesLE(BatchId),
            uid)).ToBytes().Take(7).ToArray();
    }
}
