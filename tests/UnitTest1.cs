using System.Collections;
using System.Text.RegularExpressions;
using BTCPayServer.NTag424.PCSC;
using NdefLibrary.Ndef;
using Newtonsoft.Json.Linq;
using Xunit.Abstractions;

namespace BTCPayServer.NTag424.Tests;

public class UnitTest1
{
    public ITestOutputHelper Logs { get; }

    public UnitTest1(ITestOutputHelper logs)
    {
        Logs = logs;
    }
    [Fact]
    public void CanCreateAPDUFromNtagCommand()
    {
        var actual = (NtagCommands.ISOSelectFile with
        {
            P1 = 0x04,
            P2 = 0x00,
            Data = "d2760000850101".HexToBytes()
        }).ToBytes().ToHex();
        var expected = "00A4040007D2760000850101".ToLowerInvariant();
        Assert.Equal(expected, actual);

        actual = (NtagCommands.ISOSelectFile with
        {
            P1 = 0x04,
            P2 = 0x00,
            Data = "d2760000850101".HexToBytes(),
            Le = 0
        }).ToBytes().ToHex();
        expected = "00A4040007D276000085010100".ToLowerInvariant();
        Assert.Equal(expected, actual);
    }

    //from https://github.com/boltcard/boltcard/blob/7745c9f20d5ad0129cb4b3fc534441038e79f5e6/docs/TEST_VECTORS.md
    [Theory]
    [InlineData("E19CCB1FED8892CE", "04996c6a926980", 3)]
    [InlineData("66B4826EA4C155B4", "04996c6a926980", 5)]
    [InlineData("CC61660C020B4D96", "04996c6a926980", 7)]
    public void CanCalculateSunMac(string expected, string uid, int ctr)
    {
        var key = new AESKey(Convert.FromHexString("b45775776cb224c75bcde7ca3704e933"));
        var actual = key.GetSunMac(uid.HexToBytes(), ctr);
        Assert.Equal(expected.ToLowerInvariant(), actual.ToHex());
    }

    //from https://github.com/boltcard/boltcard/blob/7745c9f20d5ad0129cb4b3fc534441038e79f5e6/docs/TEST_VECTORS.md
    [Theory]
    [InlineData("4E2E289D945A66BB13377A728884E867", "04996c6a926980", 3)]
    [InlineData("00F48C4F8E386DED06BCDC78FA92E2FE", "04996c6a926980", 5)]
    [InlineData("0DBF3C59B59B0638D60B5842A997D4D1", "04996c6a926980", 7)]
    public void CanDecryptSunPICCData(string encrypted, string uid, int ctr)
    {
        var key = new AESKey(Convert.FromHexString("0c3b25d92b38ae443229dd59ad34b85d"));
        var picc = PICCData.Create(key.Decrypt(encrypted.HexToBytes()));
        Assert.Equal(ctr, picc.Counter);
        Assert.Equal(uid.ToLowerInvariant(), picc.Uid?.ToHex());
    }

    [Theory]
    [InlineData("01020304050607080910111213141516", "0102030405060708091011121314151680000000000000000000000000000000")]
    [InlineData("010203040506070809101112131415", "01020304050607080910111213141580")]
    [InlineData("01", "01800000000000000000000000000000")]
    public void CanDoPadding(string data, string padded)
    {
        var actual = Ntag424.Session.PaddingForEnc(data.HexToBytes()).ToHex();
        Assert.Equal(padded, actual);
    }

    [Fact]
    public void CanDeriveDeterministicBoltcard()
    {
        var issuerKey = new AESKey("00000000000000000000000000000001".HexToBytes());
        var batchId = 1U;
        var uid = "04a39493cc8680".HexToBytes();
        var batchKeys = new DeterministicBatchKeys(issuerKey, batchId);
        var keys = batchKeys.DeriveBoltcardKeys(uid);
        Logs.WriteLine("K0: " + keys.AppMasterKey.ToBytes().ToHex());
        Logs.WriteLine("K1: " + keys.EncryptionKey.ToBytes().ToHex());
        Logs.WriteLine("K2: " + keys.AuthenticationKey.ToBytes().ToHex());
        Logs.WriteLine("K3: " + keys.K3.ToBytes().ToHex());
        Logs.WriteLine("K4: " + keys.K4.ToBytes().ToHex());
        Logs.WriteLine("ID: " + batchKeys.GetId(uid).ToHex());
    }

    [Fact]
    public void CanCreateCommModeMAC()
    {
        var session = new Ntag424.Session(0, AESKey.Default, new AESKey(new byte[16]), new AESKey("8248134A386E86EB7FAF54A52E536CB6".HexToBytes()), "7A21085E".HexToBytes());
        var command = NtagCommands.GetFileSettings with
        {
            CommMode = CommMode.MAC,
            Data = new byte[] { 0x02 }
        };
        command = command.Encode(session);
        var apdu = command.ToBytes().ToHex();
        Assert.Equal("90F5000009026597A457C8CD442C00".ToLower(), apdu);
        var resp = new NtagResponse("0040EEEE000100D1FE001F00004400004400002000006A00002A474282E7A47986".HexToBytes(), 0x9100);
        command.ThrowIfUnexpected(resp);
        session.Counter++;
        var respData = resp.Decode(session, CommMode.MAC).Data.ToHex();
        Assert.Equal("0040EEEE000100D1FE001F00004400004400002000006A0000".ToLower(), respData);
    }
    [Fact]
    public void CanCreateCommModeFull()
    {
        var session = new Ntag424.Session(0, AESKey.Default, new AESKey("7305E2CCA5B0377617CDBFEB96C9B358".HexToBytes()), new AESKey("8B485037C8C2FB400D79BF0AB956F28F".HexToBytes()), "856C1841".HexToBytes());
        var command = NtagCommands.WriteData with
        {
            CommMode = CommMode.Full,
            Data = "02000000800000005ED1015B5500687474703A2F2F7777772E6D69666172652E6E65742F70726F64756374732F6E746167733F265549443D3034323136353441434634433830264374723D30303030303126436D61633D323145323336303832363645334345410000000000000000000000000000000000000000000000000000000000000000".HexToBytes()
        };
        command = command.Encode(session);
        var apdu = command.ToBytes().ToHex();
        // Why there are 4 more bytes in the doc??
        // Original:  908D00009F02000000800000B4716C58E71A09F6D869AB7810C2E94BD02F13DF2159433D581F50185B11535F3E7A068582B04B5E4BDE374A788DF7AD8C4C5473F7B30D9496BD8F3F8ED51D506D3194FDEA51A877C2EB28A0A8FD2B34E196800A7D2F0AD1CBED98E311E2F7667DA10DF3CF4CE6A5658B89695EDAD9F500000000D9AD1E4C41748D34BC6B15A2B45B050F34765F3E9D2CF701E0C7F781477F7B91B97CBB2A236F876C00
        Assert.Equal("908D00009F02000000800000B4716C58E71A09F6D869AB7810C2E94BD02F13DF2159433D581F50185B11535F3E7A068582B04B5E4BDE374A788DF7AD8C4C5473F7B30D9496BD8F3F8ED51D506D3194FDEA51A877C2EB28A0A8FD2B34E196800A7D2F0AD1CBED98E311E2F7667DA10DF3CF4CE6A5658B89695EDAD9F5D9AD1E4C41748D34BC6B15A2B45B050F34765F3E9D2CF701E0C7F781477F7B91B97CBB2A236F876C00".ToLower(), apdu);

        var resp = new NtagResponse("DDDB9EC959B3EFEB".HexToBytes(), 0x9100);
        command.ThrowIfUnexpected(resp);

        session.Counter++;
        var respData = resp.Decode(session, CommMode.MAC).Data.ToHex();
        Assert.Empty(respData);
    }

    [Fact]
    public void CanCreateFileSettings()
    {
        var actual = new FileSettings(DataFile.NDEF)
        {
            AccessRights = new()
            {
                ReadWrite = AccessCondition.Key0,
                Change = AccessCondition.Key0,
                Write = AccessCondition.Key0,
                Read = AccessCondition.Free
            },
            SDMMirroring = true,
            SDMUID = true,
            SDMReadCtr = true,
            SDMAccessRights = new()
            {
                MetaRead = AccessCondition.Key1,
                FileRead = AccessCondition.Key2,
                CtrRet = AccessCondition.Never
            },
            PICCDataOffset = 3,
            SDMMACOffset = 2,
            SDMMACInputOffset = 1
        }.ToBytes().ToHex();

        Assert.Equal("4000E0C1FF12030000010000020000".ToLower(), actual);
    }

    [Fact]
    public async Task CanAuthenticate()
    {
        using var ctx = PCSCContext.Create();
        var ntag = ctx.CreateNTag424();
        var key = AESKey.Default;
        await ntag.AuthenticateEV2First(0, key);
        var uid1 = await ntag.GetCardUID();
        await ntag.AuthenticateEV2NonFirst(1, key);
        var uid2 = await ntag.GetCardUID();
        Assert.Equal(uid1.ToHex(), uid2.ToHex());
    }

    [Fact]
    public async Task Reset()
    {
        var issuerKey = new AESKey("01000000000000000000000000000000".HexToBytes());
        var batchKeys = new DeterministicBatchKeys(issuerKey);
        using var ctx = PCSCContext.Create();
        var enc = batchKeys.DeriveEncryptionKey();
        var ntag = ctx.CreateNTag424();
        await ntag.AuthenticateEV2First(1, enc);
        var uid = await ntag.GetCardUID();
        var keys = batchKeys.DeriveBoltcardKeys(uid);
        await ntag.ResetCard(keys);
    }

    [Fact]
    public async Task CanChangeKey()
    {
        using var ctx = PCSCContext.Create();
        var ntag = ctx.CreateNTag424();
        var key1 = AESKey.Default;
        var key2b = new byte[16];
        key2b[^1] = 1;
        var key2 = new AESKey(key2b);
        await ntag.AuthenticateEV2First(0, key1);
        await ntag.ChangeKey(0, key1);

        await ntag.AuthenticateEV2First(0, key1);
        await ntag.ChangeKey(1, key1);
        await ntag.ChangeKey(1, key2, key1);
        await ntag.ChangeKey(1, key1, key2);
    }

    [Fact]
    public async Task CanWaitForCard()
    {
        await PCSCContext.WaitForCard();
    }

    [Fact]
    public async Task CanDoBoltcard()
    {
        using var ctx = PCSCContext.Create();
        var ntag = ctx.CreateNTag424();
        var keys = new BoltcardKeys(
            AppMasterKey: new AESKey("00000000000000000000000000000001".HexToBytes()),
            EncryptionKey: new AESKey("00000000000000000000000000000002".HexToBytes()),
            AuthenticationKey: new AESKey("00000000000000000000000000000003".HexToBytes()),
            K3: new AESKey("00000000000000000000000000000004".HexToBytes()),
            K4: new AESKey("00000000000000000000000000000005".HexToBytes()));
        //await ntag.ResetCard(keys);
        await ntag.SetupBoltcard("http://test.com", BoltcardKeys.Default, keys);
        var message = await ntag.ReadNDef();
        var uri = new NdefUriRecord(message[0]).Uri;
        var p = Regex.Match(uri, "p=(.*?)&").Groups[1].Value;
        var c = Regex.Match(uri, "c=(.*)").Groups[1].Value;
        var piccData = PICCData.Create(keys.EncryptionKey.Decrypt(p));
        Assert.True(keys.AuthenticationKey.CheckSunMac(c, piccData));
        await ntag.ResetCard(keys);
    }

    [Fact]
    public async Task CanDoDeterministicBoltcard()
    {
        using var ctx = PCSCContext.Create();
        var ntag = ctx.CreateNTag424();
        var issuerKey = new AESKey("00000000000000000000000000000001".HexToBytes());
        //await ntag.ResetCard(issuerKey);
        await ntag.AuthenticateEV2First(0, AESKey.Default);
        var uid = await ntag.GetCardUID();
        var batchKeys = new DeterministicBatchKeys(issuerKey);
        var keys = batchKeys.DeriveBoltcardKeys(uid);

        await ntag.SetupBoltcard("http://test.com", BoltcardKeys.Default, keys);
        var message = await ntag.ReadNDef();
        var uri = new NdefUriRecord(message[0]).Uri;
        var p = Regex.Match(uri, "p=(.*?)&").Groups[1].Value;
        var c = Regex.Match(uri, "c=(.*)").Groups[1].Value;

        var piccData = PICCData.TryDeterministicBoltcardDecrypt(batchKeys, p, c);
        Assert.NotNull(piccData);
        await ntag.ResetCard(batchKeys);
    }

    [Fact]
    public void CanCalculateCRC()
    {
        var bytes = new byte[] { 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100 };
        var result = Helpers.CRCJam(bytes);
        Assert.Equal(unchecked((uint)(-0xd4a1186)), result);
    }
}
