using System;
using System.Security;
using System.Security.Cryptography;
using System.Threading.Tasks;
using NdefLibrary.Ndef;
using static BTCPayServer.NTag424.Helpers;

namespace BTCPayServer.NTag424;

public enum ISOLevel
{
    PICC, // MF
    Application // DF
}
public enum DataFile
{
    CC = 0xE103,
    NDEF = 0xE104,
    Proprietary = 0xE105
}

public class Ntag424
{
    public record Session(int KeyNo, AESKey Key, AESKey ENCKey, AESKey MACKey, byte[] TransactionId)
    {
        public int Counter { get; set; }

        public byte[] EncryptCommand(byte[] data)
        {
            if (data.Length == 0)
                return data;
            data = PaddingForEnc(data);
            var iv = ENCKey.Encrypt(
                Concat(
                    "A55A".HexToBytes(),
                    TransactionId,
                    UShortToBytesLE(Counter),
                    "0000000000000000".HexToBytes()
                ), null, CipherMode.ECB
            );
            return ENCKey.Encrypt(data, iv);
        }

        internal static byte[] PaddingForEnc(byte[] data)
        {
            var len = data.Length;
            var paddingLen = 16 - (len % 16);
            var padded = new byte[len + paddingLen];
            Array.Copy(data, padded, len);
            padded[len] = 0x80;
            return padded;
        }


        public byte[] DecryptResponse(byte rc, byte[] data, CommMode commMode)
        {
            if (commMode is CommMode.Plain || data.Length == 0)
                return data;
            var mac = data[^8..];
            data = data[..^8];
            var expectedMac = this.GetMac(rc, data);
            if (!expectedMac.IsSame(mac))
                throw new UnexpectedResponseException("Invalid MAC");
            if (data.Length == 0 || commMode == CommMode.MAC)
                return data;
            var iv = ENCKey.Encrypt(
                Concat(
                    "5AA5".HexToBytes(),
                    TransactionId,
                    UShortToBytesLE(Counter),
                    "0000000000000000".HexToBytes()
                ), null, CipherMode.ECB
            );
            var decrypted = ENCKey.Decrypt(data, iv);
            var paddingStart = Array.LastIndexOf(decrypted, (byte)0x80);
            return decrypted[0..paddingStart];
        }

        public byte[] GetMac(byte ins, byte[]? data)
        {
            var macValue = Concat(
            new byte[] { ins },
            UShortToBytesLE(Counter),
            TransactionId,
            data ?? Array.Empty<byte>());
            var mac = MACKey.CMac(macValue);
            return Truncate(mac);
        }
    }
    readonly IAPDUTransport Transport;
    public Ntag424(IAPDUTransport transport)
    {
        Transport = transport;
    }
    public Session? CurrentSession { get; private set; }

    public async Task IsoSelectFile(ISOLevel level)
    {
        await SendAPDU(NtagCommands.ISOSelectFile with
        {
            P1 = 0x04,
            P2 = 0x00,
            Data = (level switch
            {
                ISOLevel.PICC => "d2760000850100",
                ISOLevel.Application => "d2760000850101",
                _ => throw new ArgumentException(nameof(level))
            }).HexToBytes()
        });
    }
    public async Task IsoSelectFile(DataFile file)
    {
        await SendAPDU(NtagCommands.ISOSelectFile with
        {
            P1 = 0x00,
            P2 = 0x00,
            Data = new byte[] { (byte)((int)file >> 8), (byte)file },
            Le = 0
        });
    }

    public Task<Session> AuthenticateEV2NonFirst(int keyNo, AESKey key)
    {
        return AuthenticateEV2(keyNo, key, false);
    }
    public Task<Session> AuthenticateEV2First(int keyNo, AESKey key)
    {
        return AuthenticateEV2(keyNo, key, true);
    }
    async Task<Session> AuthenticateEV2(int keyNo, AESKey key, bool first)
    {
        int sessionCounter = CurrentSession?.Counter ?? 0;
        if (first)
        {
            await IsoSelectFile(ISOLevel.Application);
            sessionCounter = 0;
        }
        else
        {
            if (CurrentSession is null)
                throw new InvalidOperationException("Authentication required for AuthenticateEV2NonFirst");
            sessionCounter = CurrentSession.Counter;
        }

        NtagResponse resp;
        if (first)
        {
            resp = await SendAPDU(NtagCommands.AuthenticateEV2FirstPart1 with
            {
                Data = $"{(byte)keyNo:x2}03000000".HexToBytes()
            });
        }
        else
        {
            resp = await SendAPDU(NtagCommands.AuthenticateEV2NonFirstPart1 with
            {
                Data = new byte[] { (byte)keyNo }
            });
        }
        var rndB = key.Decrypt(resp.Data);
        var rndBp = RotateLeft(rndB);
        var rndA = RandomNumberGenerator.GetBytes(16);
        var encRnd = key.Encrypt(Concat(rndA, rndBp));
        var secondPart = first ? NtagCommands.AuthenticateEV2FirstPart2 : NtagCommands.AuthenticateEV2NonFirstPart2;
        resp = await SendAPDU(secondPart with
        {
            Data = encRnd
        });

        var data = key.Decrypt(resp.Data);
        var rndAp = RotateLeft(rndA);
        byte[] tid;
        byte[] actualRndAp;
        if (first)
        {
            tid = data[0..4];
            actualRndAp = data[4..20];
        }
        else
        {
            tid = CurrentSession!.TransactionId;
            actualRndAp = data[0..16];
        }
        if (!rndAp.IsSame(actualRndAp))
            throw new UnexpectedResponseException("Invalid RndAp response");
        var rndMix = Concat(
            rndA[0..2],
            XOR(rndA[2..8], rndB[0..6]),
            rndB[6..16],
            rndA[8..16]);
        var encKey = key.Derive(Concat(
            "A55A00010080".HexToBytes(),
            rndMix));
        var macKey = key.Derive(Concat(
            "5AA500010080".HexToBytes(),
            rndMix));
        var session = new Session(keyNo, key, encKey, macKey, tid)
        {
            Counter = sessionCounter
        };
        CurrentSession = session;
        return session;
    }

    private async Task<NtagResponse> SendAPDU(NTagCommand command)
    {
        CommMode commandMode;
        if (command.CommMode is CommMode m)
        {
            commandMode = m;
        }
        else
        {
            commandMode = CurrentSession is null ? CommMode.Plain : CommMode.Full;
            command = command with
            {
                CommMode = commandMode
            };
        }
        if (commandMode is not CommMode.Plain)
        {
            if (CurrentSession is null)
                throw new InvalidOperationException("Authentication required");
            command = command.Encode(CurrentSession);
        }
        if (CurrentSession is not null)
            CurrentSession.Counter++;

        var resp = await Transport.SendAPDU(command);
        command.ThrowIfUnexpected(resp);
        if (commandMode is not CommMode.Plain && CurrentSession is not null)
        {
            resp = resp.Decode(CurrentSession, commandMode);
        }
        return resp;
    }

    public async Task<byte[]> GetCardUID()
    {
        return (await SendAPDU(NtagCommands.GetCardUID)).Data;
    }

    public async Task SetRandomUID()
    {
        await SendAPDU(NtagCommands.SetConfiguration with
        {
            Data = new byte[] { 0x00, 0x02 }
        });
    }

    public async Task<FileSettings> GetFileSettings(DataFile file = DataFile.NDEF)
    {
        return new FileSettings((await SendAPDU(NtagCommands.GetFileSettings with
        {
            Data = GetFileNo(file)
        })).Data, false);
    }
    public async Task ChangeFileSettings(DataFile file = DataFile.NDEF, FileSettings? fileSettings = null)
    {
        fileSettings ??= new FileSettings(file);
        await SendAPDU(NtagCommands.ChangeFileSettings with
        {
            Data = Concat(
                GetFileNo(file),
                fileSettings.ToBytes()
            )
        });
    }

    public async Task<NdefMessage> ReadNDef()
    {
        await IsoSelectFile(ISOLevel.Application);
        await IsoSelectFile(DataFile.NDEF);
        var size = (await SendAPDU(NtagCommands.ISOReadBinary with
        {
            P1 = 0,
            P2 = 0,
            Le = 2
        })).Data[1];
        var data = (await SendAPDU(NtagCommands.ISOReadBinary with
        {
            P1 = 0,
            P2 = 2,
            Le = size
        })).Data;
        CurrentSession = null;
        return NdefMessage.FromByteArray(data);
    }

    public async Task<byte[]> ReadFile(DataFile file, int offset, int length)
    {
        var commMode = await GetCommMode(file, AccessRight.Read);
        return (await SendAPDU(NtagCommands.ReadData with
        {
            CommMode = commMode,
            CommandHeaderSize = 7,
            Data = Concat(
                GetFileNo(file),
                UIntTo3BytesLE(offset),
                UIntTo3BytesLE(length)
            )
        })).Data;
    }

    private async Task<CommMode> GetCommMode(DataFile file, AccessRight requiredRight)
    {
        if (CurrentSession is null)
            return CommMode.Plain;
        var settings = await GetFileSettings(file);
        if (!settings.IsAllowed(CurrentSession.KeyNo, requiredRight))
            throw new SecurityException($"The key {CurrentSession.KeyNo} doesn't have the necessary permissions");
        return settings.CommMode;
    }

    private static byte[] GetFileNo(DataFile file)
    {
        return new byte[] { file switch
        {
            DataFile.CC => 0x01,
            DataFile.NDEF => 0x02,
            DataFile.Proprietary => 0x03,
            _ => throw new ArgumentException(nameof(file))
        } };
    }

    public async Task WriteNDef(NdefMessage message)
    {
        var ndefMessageBytes = message.ToByteArray();
        var content = new byte[220]; // Normally we have 256 bytes, but APDU has a size limit we need some margin
        content[0] = (byte)(ndefMessageBytes.Length >> 8);
        content[1] = (byte)ndefMessageBytes.Length;
        Array.Copy(ndefMessageBytes, 0, content, 2, Math.Min(content.Length - 2, ndefMessageBytes.Length));
        await SendAPDU(NtagCommands.WriteData with
        {
            CommMode = await GetCommMode(DataFile.NDEF, AccessRight.Write),
            Data = Concat(
                GetFileNo(DataFile.NDEF),
                new byte[] { 0x00, 0x00, 0x00 },
                UIntTo3BytesLE(content.Length),
                content
            )
        });
    }

    public async Task ChangeKey(int keyNo, AESKey newKey, AESKey? oldKey = null, int version = 0)
    {
        if (CurrentSession is null || CurrentSession.KeyNo != 0)
            throw new InvalidOperationException("Authentication required with KeyNo 0");

        byte[] data;
        if (keyNo == 0)
        {
            data = Concat(
                    newKey.ToBytes(),
                    new byte[] { (byte)version }
                );
        }
        else
        {
            oldKey ??= new AESKey(new byte[16]);
            data = Concat(
                XOR(newKey.ToBytes(), oldKey.ToBytes()),
                new byte[] { (byte)version },
                UIntToBytesLE(CRCJam(newKey.ToBytes())));
        }

        await SendAPDU(NtagCommands.ChangeKey with
        {
            Data = Concat(
                new byte[] { (byte)keyNo },
                data
            )
        });
        if (keyNo == 0)
            CurrentSession = null;
    }

    public async Task ResetCard(AESKey issuerKey, uint batchId = 0)
    {
        if (CurrentSession is null)
            await AuthenticateEV2First(0, issuerKey);
        if (issuerKey != CurrentSession!.Key)
            await AuthenticateEV2NonFirst(0, issuerKey);
        var uid = await GetCardUID();
        var keys = BoltcardKeys.CreateDeterministicKeys(issuerKey, uid, batchId);
        await ResetCard(keys);
    }
    public async Task ResetCard(BoltcardKeys keys)
    {
        if (CurrentSession is null)
            await AuthenticateEV2First(0, keys.IssuerKey);
        if (keys.IssuerKey != CurrentSession!.Key)
            await AuthenticateEV2NonFirst(0, keys.IssuerKey);

        if (CurrentSession!.KeyNo != 0)
            throw new InvalidOperationException("Authentication required with KeyNo 0");

        await ChangeFileSettings(file: DataFile.NDEF, new FileSettings(DataFile.NDEF));

        await ChangeKey(4, AESKey.Default, keys.K4);
        await ChangeKey(3, AESKey.Default, keys.K3);
        await ChangeKey(2, AESKey.Default, keys.AuthenticationKey);
        await ChangeKey(1, AESKey.Default, keys.EncryptionKey);
        await ChangeKey(0, AESKey.Default);
    }

    /// <summary>
    /// Setup a bolt card
    /// </summary>
    /// <param name="issuerKey">The AppMasterKey, the key that must be used to reset the card or change settings.</param>
    /// <param name="encryptionKey">The key used to encrypt p=</param>
    /// <param name="authenticationKey">The key used for authentifying the card</param>
    /// <param name="lnurlw"></param>
    /// <returns></returns>
    public async Task SetupBoltcard(
        string lnurlw,
        BoltcardKeys oldKeys,
        BoltcardKeys newKeys)
    {
        if (CurrentSession is null)
            await AuthenticateEV2First(0, oldKeys.IssuerKey);
        if (newKeys.IssuerKey != CurrentSession!.Key && CurrentSession.KeyNo != 0)
            throw new InvalidOperationException("Authentication required with KeyNo 0");

        if (!lnurlw.Contains('?', StringComparison.OrdinalIgnoreCase))
            lnurlw += "?";
        else
            lnurlw += "&";
        lnurlw += "p=00000000000000000000000000000000&c=0000000000000000";

        var ndef = new NdefMessage
        {
            new NdefUriRecord() { Uri = lnurlw }
        };
        await WriteNDef(ndef);
        var ndefBytes = ndef.ToByteArray();
        var pIndex = Array.LastIndexOf(ndefBytes, (byte)'p') + 4;
        var cIndex = Array.LastIndexOf(ndefBytes, (byte)'c') + 4;
        var settings = new FileSettings(DataFile.NDEF)
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
            SDMMACInputOffset = cIndex,
            SDMMACOffset = cIndex,
            PICCDataOffset = pIndex
        };
        await ChangeFileSettings(fileSettings: settings);
        await SetRandomUID();
        if (newKeys.EncryptionKey != oldKeys.EncryptionKey)
            await ChangeKey(1, newKeys.EncryptionKey, oldKeys.EncryptionKey);

        if (newKeys.AuthenticationKey != oldKeys.AuthenticationKey)
            await ChangeKey(2, newKeys.AuthenticationKey, oldKeys.AuthenticationKey);

        if (newKeys.K3 != oldKeys.K3)
            await ChangeKey(3, newKeys.K3, oldKeys.K3);

        if (newKeys.K4 != oldKeys.K4)
            await ChangeKey(4, newKeys.K4, oldKeys.K4);

        if (newKeys.IssuerKey != CurrentSession!.Key)
        {
            await ChangeKey(0, newKeys.IssuerKey); // No need of old key for 0
            await AuthenticateEV2First(0, newKeys.IssuerKey);
        }
    }
}
