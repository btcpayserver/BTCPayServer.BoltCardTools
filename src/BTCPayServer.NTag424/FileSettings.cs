using System;
using System.Collections.Generic;

namespace BTCPayServer.NTag424;

public enum AccessCondition
{
    Key0 = 0, Key1 = 1, Key2 = 2, Key3 = 3, Key4 = 4,
    Free = 0x0E, Never = 0x0F
}
public enum AccessRight
{
    Read,
    Write,
    Change
}

public record SDMAccessRights
{
    public SDMAccessRights()
    {
        MetaRead = AccessCondition.Never;
        FileRead = AccessCondition.Never;
        CtrRet = AccessCondition.Never;
    }
    public SDMAccessRights(ReadOnlySpan<byte> conditions)
    {
        MetaRead = (AccessCondition)((byte)(conditions[1] & 0b1111_0000) >> 4);
        FileRead = (AccessCondition)(conditions[1] & 0b0000_1111);
        CtrRet = (AccessCondition)(conditions[0] & 0b0000_1111);
    }
    public AccessCondition MetaRead { get; set; }
    public AccessCondition FileRead { get; set; }
    public AccessCondition CtrRet { get; set; }
    public byte[] ToBytes()
    {
        var fileSettings = new byte[2];
        fileSettings[1] = (byte)(((byte)MetaRead << 4) | ((byte)FileRead & 0b0000_1111));
        fileSettings[0] = (byte)(((byte)CtrRet & 0b0000_1111) | (byte)0xf0);
        return fileSettings;
    }
}
public record AccessRights
{
    public AccessRights(ReadOnlySpan<byte> conditions)
    {
        Read = (AccessCondition)((byte)(conditions[1] & 0b1111_0000) >> 4);
        Write = (AccessCondition)(conditions[1] & 0b0000_1111);
        ReadWrite = (AccessCondition)((byte)(conditions[0] & 0b1111_0000) >> 4);
        Change = (AccessCondition)(conditions[0] & 0b0000_1111);
    }
    public AccessRights() : this(DataFile.NDEF)
    {

    }
    public AccessRights(DataFile file)
    {
        if (file == DataFile.CC)
        {
            Read = AccessCondition.Free;
            Write = AccessCondition.Key0;
            ReadWrite = AccessCondition.Key0;
            Change = AccessCondition.Key0;
        }
        else if (file == DataFile.NDEF)
        {
            Read = AccessCondition.Free;
            Write = AccessCondition.Free;
            ReadWrite = AccessCondition.Free;
            Change = AccessCondition.Key0;
        }
        else
        {
            Read = AccessCondition.Key2;
            Write = AccessCondition.Key3;
            ReadWrite = AccessCondition.Key3;
            Change = AccessCondition.Key0;
        }
    }

    public bool IsAllowed(int keyNo, AccessRight right)
    {
        var keyno = (AccessCondition)keyNo;
        if (right == AccessRight.Change)
            return Change == keyno || Change == AccessCondition.Free;
        if (ReadWrite == keyno || ReadWrite == AccessCondition.Free)
            return true;
        if (right == AccessRight.Write)
            return Write == keyno || Write == AccessCondition.Free;
        if (right == AccessRight.Read)
            return Read == keyno || Read == AccessCondition.Free;
        return false;
    }

    public AccessCondition Write { get; set; }
    public AccessCondition ReadWrite { get; set; }
    public AccessCondition Read { get; set; }
    public AccessCondition Change { get; set; }
    public byte[] ToBytes()
    {
        var fileSettings = new byte[2];
        fileSettings[1] = (byte)(((byte)Read << 4) | ((byte)Write & 0b0000_1111));
        fileSettings[0] = (byte)(((byte)ReadWrite << 4) | ((byte)Change & 0b0000_1111));
        return fileSettings;
    }
}

public record FileSettings
{
    public FileSettings(DataFile file)
    {
        SDMMirroring = false;
        CommMode = CommMode.Plain;
        AccessRights = new AccessRights(file);
    }
    public FileSettings(byte[] fileSettings, bool update)
    {
        int i = 0;
        if (!update)
        {
            i++;
        }
        SDMMirroring = (fileSettings[i] & 0b0100_0000) != 0;
        CommMode = (fileSettings[i] & 0b0000_0011) switch
        {
            0b01 => CommMode.MAC,
            0b11 => CommMode.Full,
            _ => CommMode.Plain
        };
        i++;
        AccessRights = new AccessRights(fileSettings[i..(i + 2)]);
        i += 2;
        if (!update)
        {
            i += 3; // Size
        }
        if (!SDMMirroring)
            return;
        var sdmOptions = fileSettings[i];
        SDMUID = (0b1000_0000 & sdmOptions) != 0;
        SDMReadCtr = (0b0100_0000 & sdmOptions) != 0;
        SDMReadCtrLimit = (0b0010_0000 & sdmOptions) != 0;
        SDMENCFileData = (0b0001_0000 & sdmOptions) != 0;
        i++;
        SDMAccessRights = new SDMAccessRights(fileSettings[i..(i + 2)]);
        i += 2;
        if (SDMUID && SDMAccessRights.MetaRead == AccessCondition.Free)
        {
            UIDOffset = Helpers.BytesToUIntLE(fileSettings[i..(i + 3)]);
            i += 3;
        }
        if (SDMReadCtr && SDMAccessRights.MetaRead == AccessCondition.Free)
        {
            SDMReadCtrOffset = Helpers.BytesToUIntLE(fileSettings[i..(i + 3)]);
            i += 3;
        }
        if (SDMAccessRights.MetaRead != AccessCondition.Free && SDMAccessRights.MetaRead != AccessCondition.Never)
        {
            PICCDataOffset = Helpers.BytesToUIntLE(fileSettings[i..(i + 3)]);
            i += 3;
        }
        if (SDMAccessRights.FileRead != AccessCondition.Never)
        {
            SDMMACInputOffset = Helpers.BytesToUIntLE(fileSettings[i..(i + 3)]);
            i += 3;
        }
        if (SDMAccessRights.FileRead != AccessCondition.Never && SDMENCFileData)
        {
            SDMENCOffset = Helpers.BytesToUIntLE(fileSettings[i..(i + 3)]);
            i += 3;
            SDMENCLength = Helpers.BytesToUIntLE(fileSettings[i..(i + 3)]);
            i += 3;
        }
        if (SDMAccessRights.FileRead != AccessCondition.Never)
        {
            SDMMACOffset = Helpers.BytesToUIntLE(fileSettings[i..(i + 3)]);
            i += 3;
        }
        if (SDMReadCtrLimit)
        {
            SDMReadCtrLimitValue = Helpers.BytesToUIntLE(fileSettings[i..(i + 3)]);
            i += 3;
        }
    }

    public bool SDMUID { get; set; }
    public bool SDMReadCtr { get; set; }
    public bool SDMReadCtrLimit { get; set; }
    public int SDMReadCtrLimitValue { get; set; }
    public bool SDMENCFileData { get; set; }
    public SDMAccessRights SDMAccessRights { get; set; } = new SDMAccessRights();

    public byte[] ToBytes()
    {
        List<byte> output = new List<byte>();
        byte fileOptions = CommMode switch
        {
            CommMode.MAC => 0b01,
            CommMode.Full => 0b11,
            _ => 0b00
        };
        if (SDMMirroring)
            fileOptions |= 0b0100_0000;
        output.Add(fileOptions);
        output.AddRange(AccessRights.ToBytes());
        if (!SDMMirroring)
            return output.ToArray();

        var sdmOptions = 0x01;
        if (SDMUID)
            sdmOptions |= 0b1000_0000;
        if (SDMReadCtr)
            sdmOptions |= 0b0100_0000;
        if (SDMReadCtrLimit)
            sdmOptions |= 0b0010_0000;
        if (SDMENCFileData)
            sdmOptions |= 0b0001_0000;
        output.Add((byte)sdmOptions);
        output.AddRange(SDMAccessRights.ToBytes());
        if (SDMUID && SDMAccessRights.MetaRead == AccessCondition.Free)
        {
            output.AddRange(Helpers.UIntTo3BytesLE(UIDOffset));
        }
        if (SDMReadCtr && SDMAccessRights.MetaRead == AccessCondition.Free)
        {
            output.AddRange(Helpers.UIntTo3BytesLE(SDMReadCtrOffset));
        }
        if (SDMAccessRights.MetaRead != AccessCondition.Free && SDMAccessRights.MetaRead != AccessCondition.Never)
        {
            output.AddRange(Helpers.UIntTo3BytesLE(PICCDataOffset));
        }
        if (SDMAccessRights.FileRead != AccessCondition.Never)
        {
            output.AddRange(Helpers.UIntTo3BytesLE(SDMMACInputOffset));
        }
        if (SDMAccessRights.FileRead != AccessCondition.Never && SDMENCFileData)
        {
            output.AddRange(Helpers.UIntTo3BytesLE(SDMENCOffset));
            output.AddRange(Helpers.UIntTo3BytesLE(SDMENCLength));
        }
        if (SDMAccessRights.FileRead != AccessCondition.Never)
        {
            output.AddRange(Helpers.UIntTo3BytesLE(SDMMACOffset));
        }
        if (SDMReadCtrLimit)
        {
            output.AddRange(Helpers.UIntTo3BytesLE(SDMReadCtrLimitValue));
        }
        return output.ToArray();
    }
    public int SDMMACOffset { get; set; }
    public int SDMMACInputOffset { get; set; }
    public int SDMENCLength { get; set; }
    public int SDMENCOffset { get; set; }
    public int PICCDataOffset { get; set; }
    public int SDMReadCtrOffset { get; set; }
    public int UIDOffset { get; set; }
    public AccessRights AccessRights { get; set; }

    public bool IsAllowed(int keyNo, AccessRight right) => AccessRights.IsAllowed(keyNo, right);

    public bool SDMMirroring { get; set; }
    public CommMode CommMode { get; set; }
}
