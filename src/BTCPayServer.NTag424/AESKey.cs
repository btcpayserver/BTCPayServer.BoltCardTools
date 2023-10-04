using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using static BTCPayServer.NTag424.Helpers;

namespace BTCPayServer.NTag424;

public class AESKey
{
    public const int BLOCK_SIZE = 16;
    byte[] _bytes;
    public byte[] ToBytes() => _bytes.ToArray();
    public static AESKey Parse(string hex)
    {
        return new AESKey(hex.HexToBytes());
    }
    AESKey(byte[] bytes)
    {
        AssertKeySize(bytes);
        _bytes = bytes;
    }
    public AESKey(ReadOnlySpan<byte> bytes)
    {
        AssertKeySize(bytes);
        _bytes = bytes.ToArray();
    }

    private static void AssertKeySize(ReadOnlySpan<byte> bytes)
    {
        if (bytes.Length != BLOCK_SIZE)
            throw new ArgumentException($"AES key must be {BLOCK_SIZE} bytes long");
    }

    public AESKey Derive(byte[] input)
    {
        return new AESKey(CMac(input));
    }
    public byte[] Decrypt(ReadOnlySpan<byte> cypherText, byte[]? iv = null)
    {
        iv ??= new byte[BLOCK_SIZE];
        using MemoryStream ms = new MemoryStream(cypherText.ToArray());
        using var aes = Aes.Create();
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.None;
        using var cs = new CryptoStream(ms, aes.CreateDecryptor(_bytes, iv), CryptoStreamMode.Read);
        var output = new byte[cypherText.Length];
        cs.Read(output);
        return output;
    }
    public byte[] Encrypt(byte[] clearText, byte[]? iv = null, CipherMode mode = CipherMode.CBC)
    {
        return AesEncrypt(_bytes, iv ?? new byte[BLOCK_SIZE], clearText, mode);
    }
    public byte[] GetSunMac(PICCData piccData, byte[]? payload = null)
    {
        return GetSunMac(piccData.Uid, piccData.Counter, payload);
    }
    public byte[] GetSunMac(byte[]? uid, int? counter, byte[]? payload = null)
    {
        payload ??= Array.Empty<byte>();
        var derived = SesSDMFileReadMACKey(uid, counter);
        var cmac = derived.CMac(payload);
        return Truncate(cmac);
    }
    public PICCData DecryptSun(byte[] data)
    {
        return PICCData.Create(Decrypt(data));
    }
    AESKey SesSDMFileReadMACKey(byte[]? uid, int? counter)
    {
        int i = 0;
        var sv2 = new byte[16];
        sv2[i++] = 0x3c;
        sv2[i++] = 0xc3;
        sv2[i++] = 0x00;
        sv2[i++] = 0x01;
        sv2[i++] = 0x00;
        sv2[i++] = 0x80;
        if (uid is not null)
        {
            sv2[i++] = uid[0];
            sv2[i++] = uid[1];
            sv2[i++] = uid[2];
            sv2[i++] = uid[3];
            sv2[i++] = uid[4];
            sv2[i++] = uid[5];
            sv2[i++] = uid[6];
        }
        if (counter is int)
        {
            sv2[i++] = (byte)counter;
            sv2[i++] = (byte)(counter >> 8);
            sv2[i++] = (byte)(counter >> 16);
        }
        return Derive(sv2);
    }
    private static byte[] AesEncrypt(byte[] key, byte[] iv, byte[] data, CipherMode mode = CipherMode.CBC)
    {
        using MemoryStream ms = new MemoryStream();
        using var aes = Aes.Create();
        aes.Mode = mode;
        aes.Padding = PaddingMode.None;

        using var cs = new CryptoStream(ms, aes.CreateEncryptor(key, iv), CryptoStreamMode.Write);
        cs.Write(data, 0, data.Length);
        cs.FlushFinalBlock();

        return ms.ToArray();
    }

    public byte[] CMac(byte[] data)
    {
        var key = _bytes;
        // SubKey generation
        // step 1, AES-128 with key K is applied to an all-zero input block.
        byte[] L = AesEncrypt(key, new byte[16], new byte[16]);

        // step 2, K1 is derived through the following operation:
        byte[]
            FirstSubkey =
                RotateLeft(L); //If the most significant bit of L is equal to 0, K1 is the left-shift of L by 1 bit.
        if ((L[0] & 0x80) == 0x80)
            FirstSubkey[15] ^=
                0x87; // Otherwise, K1 is the exclusive-OR of const_Rb and the left-shift of L by 1 bit.

        // step 3, K2 is derived through the following operation:
        byte[]
            SecondSubkey =
                RotateLeft(FirstSubkey); // If the most significant bit of K1 is equal to 0, K2 is the left-shift of K1 by 1 bit.
        if ((FirstSubkey[0] & 0x80) == 0x80)
            SecondSubkey[15] ^=
                0x87; // Otherwise, K2 is the exclusive-OR of const_Rb and the left-shift of K1 by 1 bit.

        // MAC computing
        if (((data.Length != 0) && (data.Length % 16 == 0)) == true)
        {
            // If the size of the input message block is equal to a positive multiple of the block size (namely, 128 bits),
            // the last block shall be exclusive-OR'ed with K1 before processing
            for (int j = 0; j < FirstSubkey.Length; j++)
                data[data.Length - 16 + j] ^= FirstSubkey[j];
        }
        else
        {
            // Otherwise, the last block shall be padded with 10^i
            byte[] padding = new byte[16 - data.Length % 16];
            padding[0] = 0x80;

            data = data.Concat(padding.AsEnumerable()).ToArray();

            // and exclusive-OR'ed with K2
            for (int j = 0; j < SecondSubkey.Length; j++)
                data[data.Length - 16 + j] ^= SecondSubkey[j];
        }

        // The result of the previous process will be the input of the last encryption.
        byte[] encResult = AesEncrypt(key, new byte[16], data);

        byte[] HashValue = new byte[16];
        Array.Copy(encResult, encResult.Length - HashValue.Length, HashValue, 0, HashValue.Length);

        return HashValue;
    }

    static byte[] RotateLeft(byte[] b)
    {
        byte[] r = new byte[b.Length];
        byte carry = 0;

        for (int i = b.Length - 1; i >= 0; i--)
        {
            ushort u = (ushort)(b[i] << 1);
            r[i] = (byte)((u & 0xff) + carry);
            carry = (byte)((u & 0xff00) >> 8);
        }

        return r;
    }
}
