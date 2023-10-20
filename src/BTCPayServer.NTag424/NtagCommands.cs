using System;
using System.Collections.Generic;
using System.Linq;
using static BTCPayServer.NTag424.Helpers;

namespace BTCPayServer.NTag424;

public enum CommMode
{
    Plain,
    Full,
    MAC
}
public record NTagError(ushort sw1sw2, string Code, string Description)
{
    public override string ToString()
    {
        return $"{Code} ({sw1sw2:x4}): {Description}";
    }
}
public record NTagCommand(string Name, byte CLA, byte INS, byte? P1, byte? P2, byte? Lc, byte[]? Data, byte? Le, ushort ExpectedStatus, CommMode? CommMode, int CommandHeaderSize = 0)
{
    public List<NTagError> ErrorCodes = new List<NTagError>();
    static List<NTagError> DefaultErrorCodes = new List<NTagError>()
    {
        new NTagError(0x9100, "OPERATION_OK", "Successful operation."),
        new NTagError(0x911C, "ILLEGAL_COMMAND_CODE", "Command code not supported."),
        new NTagError(0x911E, "INTEGRITY_ERROR", "CRC or MAC does not match data. Padding bytes not valid."),
        new NTagError(0x9140, "NO_SUCH_KEY", "Invalid key number specified."),
        new NTagError(0x917E, "LENGTH_ERROR", "Length of command string invalid."),
        new NTagError(0x919D, "PERMISSION_DENIED", "Current configuration / status does not allow the requested command."),
        new NTagError(0x919E, "PARAMETER_ERROR", "Value of the parameter(s) invalid."),
        new NTagError(0x91AD, "AUTHENTICATION_DELAY", "Currently not allowed to authenticate. Keep trying until full delay is spent."),
        new NTagError(0x91AE, "AUTHENTICATION_ERROR", "Current authentication status does not allow the requested command."),
        new NTagError(0x91AF, "ADDITIONAL_FRAME", "Additional data frame is expected to be sent."),
        new NTagError(0x91BE, "BOUNDARY_ERROR", "Attempt to read/write data from/to beyond the file’s/record’s limits. Attempt to exceed the limits of a value file."),
        new NTagError(0x91CA, "COMMAND_ABORTED", "Previous Command was not fully completed. Not all Frames were requested or provided by the PCD."),
        new NTagError(0x91F0, "FILE_NOT_FOUND", "Specified file number does not exist."),
        new NTagError(0x6700, "WRONG_LENGTH", "Wrong length; no further indication."),
        new NTagError(0x6982, "SECURITY_STATUS_NOT_SATISFIED", "Security status not satisfied."),
        new NTagError(0x6985, "CONDITIONS_OF_USE_NOT_SATISFIED", "Conditions of use not satisfied."),
        new NTagError(0x6A80, "INCORRECT_PARAMETERS_IN_DATA_FIELD", "Incorrect parameters in the command data field."),
        new NTagError(0x6A82, "FILE_OR_APPLICATION_NOT_FOUND", "File or application not found."),
        new NTagError(0x6A86, "INCORRECT_PARAMETERS_P1_P2", "Incorrect parameters P1-P2."),
        new NTagError(0x6A87, "LC_INCONSISTENT_WITH_PARAMETERS_P1_P2", "Lc inconsistent with parameters P1-P2."),
        new NTagError(0x6C00, "WRONG_LE_FIELD", "Wrong Le field."),
        new NTagError(0x6D00, "INSTRUCTION_CODE_NOT_SUPPORTED_OR_INVALID", "Instruction code not supported or invalid."),
        new NTagError(0x6E00, "CLASS_NOT_SUPPORTED", "Class not supported."),
        new NTagError(0x9000, "NORMAL_PROCESSING", "Normal processing (no further qualification).")
    };
    internal void ThrowIfUnexpected(NtagResponse resp)
    {
        if (resp.sw1sw2 != ExpectedStatus)
        {
            var errorCode = ErrorCodes.FirstOrDefault(c => c.sw1sw2 == resp.sw1sw2);
            errorCode ??= DefaultErrorCodes.FirstOrDefault(c => c.sw1sw2 == resp.sw1sw2);
            if (errorCode is null)
                throw new UnexpectedStatusException(Name, ExpectedStatus, resp.sw1sw2);
            else
                throw new UnexpectedStatusException(Name, ExpectedStatus, errorCode);
        }
    }
    public byte[] ToBytes()
    {
        var list = new List<byte>
        {
            CLA,
            INS
        };
        if (!P1.HasValue)
            throw new InvalidOperationException("P1 not provided");
        if (!P2.HasValue)
            throw new InvalidOperationException("P2 not provided");

        list.Add(P1.Value);
        list.Add(P2.Value);
        if (Data != null)
        {
            list.Add((byte)(Data.Length));
            list.AddRange(Data);
        }
        if (Le.HasValue)
        {
            list.Add(Le.Value);
        }
        return list.ToArray();
    }
    public override string ToString()
    {
        return ToBytes().ToHex();
    }

    internal NTagCommand Encode(Ntag424.Session currentSession)
    {
        if (CommMode is null)
            throw new InvalidOperationException("CommMode isn't set");
        if (CommMode is NTag424.CommMode.Plain)
            return this;
        var data = Data;
        if (CommMode is NTag424.CommMode.Full && data is not null)
        {
            var nonEncrypted = data[0..CommandHeaderSize];
            var encrypted = data[CommandHeaderSize..];
            data = Concat(nonEncrypted, currentSession.EncryptCommand(encrypted));
        }
        var mac = currentSession.GetMac(INS, data);
        data = Concat(data, mac);
        return this with
        {
            Data = data
        };
    }
}
internal class NtagCommands
{
    internal readonly static NTagCommand AuthenticateEV2FirstPart1 = new(Name: "AuthenticateEV2FirstPart1", CLA: 0x90, INS: 0x71, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x91AF, CommMode: CommMode.Plain);
    internal readonly static NTagCommand AuthenticateEV2FirstPart2 = new(Name: "AuthenticateEV2FirstPart2", CLA: 0x90, INS: 0xAF, P1: 0, P2: 0, Lc: 32, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: CommMode.Plain);
    internal readonly static NTagCommand AuthenticateEV2NonFirstPart1 = new(Name: "AuthenticateEV2NonFirstPart1", CLA: 0x90, INS: 0x77, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x91AF, CommMode: CommMode.Plain);
    internal readonly static NTagCommand AuthenticateEV2NonFirstPart2 = new(Name: "AuthenticateEV2NonFirstPart2", CLA: 0x90, INS: 0xAF, P1: 0, P2: 0, Lc: 32, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: CommMode.Plain);
    internal readonly static NTagCommand AuthenticateLRPFirstPart1 = new(Name: "AuthenticateLRPFirstPart1", CLA: 0x90, INS: 0x71, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x91AF, CommMode: null);
    internal readonly static NTagCommand AuthenticateLRPFirstPart2 = new(Name: "AuthenticateLRPFirstPart2", CLA: 0x90, INS: 0xAF, P1: 0, P2: 0, Lc: 32, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: null);
    internal readonly static NTagCommand AuthenticateLRPNonFirstPart1 = new(Name: "AuthenticateLRPNonFirstPart1", CLA: 0x90, INS: 0x77, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x91AF, CommMode: null);
    internal readonly static NTagCommand AuthenticateLRPNonFirstPart2 = new(Name: "AuthenticateLRPNonFirstPart2", CLA: 0x90, INS: 0xAF, P1: 0, P2: 0, Lc: 32, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: null);
    internal readonly static NTagCommand ChangeFileSettings = new(Name: "ChangeFileSettings", CLA: 0x90, INS: 0x5F, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: CommMode.Full, CommandHeaderSize: 1);
    internal readonly static NTagCommand ChangeKey = new(Name: "ChangeKey", CLA: 0x90, INS: 0xC4, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: CommMode.Full, CommandHeaderSize: 1)
    {
        ErrorCodes =
        {
            new NTagError(0x91CA, "COMMAND_ABORTED", "Chained command or multiple pass command ongoing."),
            new NTagError(0x911E, "INTEGRITY_ERROR", "Integrity error in cryptogram or invalid secure messaging MAC (Secure Messaging)."),
            new NTagError(0x917E, "LENGTH_ERROR", "Command size not allowed."),
            new NTagError(0x919E, "PARAMETER_ERROR", "Parameter value not allowed."),
            new NTagError(0x9140, "NO_SUCH_KEY", "Targeted key does not exist."),
            new NTagError(0x919D, "PERMISSION_DENIED", "At PICC level, targeting any OriginalityKey which cannot be changed."),
            new NTagError(0x91AE, "AUTHENTICATION_ERROR", "At application level, missing active authentication with AppMasterKey while targeting any AppKey."),
            new NTagError(0x91EE, "MEMORY_ERROR", "Failure when reading or writing to non-volatile memory.")
        }
    };
    internal readonly static NTagCommand GetCardUID = new(Name: "GetCardUID", CLA: 0x90, INS: 0x51, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: CommMode.Full);
    internal readonly static NTagCommand GetFileCounters = new(Name: "GetFileCounters", CLA: 0x90, INS: 0xF6, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: CommMode.Full);
    internal readonly static NTagCommand GetFileSettings = new(Name: "GetFileSettings", CLA: 0x90, INS: 0xF5, P1: 0, P2: 0, Lc: 1, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: CommMode.MAC)
    {
        ErrorCodes =
        {
            new NTagError(0x91CA, "COMMAND_ABORTED", "Chained command or multiple pass command ongoing."),
            new NTagError(0x911E, "INTEGRITY_ERROR", "Invalid secure messaging MAC (only)."),
            new NTagError(0x917E, "LENGTH_ERROR", "Command size not allowed."),
            new NTagError(0x919E, "PARAMETER_ERROR", "Parameter value not allowed."),
            new NTagError(0x919D, "PERMISSION_DENIED", "PICC level (MF) is selected."),
            new NTagError(0x91F0, "FILE_NOT_FOUND", "File with targeted FileNo does not exist for the targeted application."),
            new NTagError(0x91EE, "MEMORY_ERROR", "Failure when reading or writing to non-volatile memory.")
        }
    };
    internal readonly static NTagCommand GetKeyVersion = new(Name: "GetKeyVersion", CLA: 0x90, INS: 0x64, P1: 0, P2: 0, Lc: 1, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: CommMode.MAC);
    internal readonly static NTagCommand GetVersionPart1 = new(Name: "GetVersionPart1", CLA: 0x90, INS: 0x60, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x91AF, CommMode: CommMode.MAC);
    internal readonly static NTagCommand GetVersionPart2 = new(Name: "GetVersionPart2", CLA: 0x90, INS: 0xAF, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x91AF, CommMode: CommMode.MAC);
    internal readonly static NTagCommand GetVersionPart3 = new(Name: "GetVersionPart3", CLA: 0x90, INS: 0xAF, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: CommMode.MAC);
    internal readonly static NTagCommand ISOReadBinary = new(Name: "ISOReadBinary", CLA: 0x00, INS: 0xB0, P1: null, P2: null, Lc: null, Data: null, Le: null, ExpectedStatus: 0x9000, CommMode: CommMode.Plain);
    internal readonly static NTagCommand ReadData = new(Name: "ReadData", CLA: 0x90, INS: 0xAD, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: null, CommandHeaderSize: 7);
    internal readonly static NTagCommand Read_Sig = new(Name: "Read_Sig", CLA: 0x90, INS: 0x3C, P1: 0, P2: 0, Lc: 1, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: CommMode.Full);
    internal readonly static NTagCommand ISOSelectFile = new(Name: "ISOSelectFile", CLA: 0x00, INS: 0xA4, P1: null, P2: null, Lc: null, Data: null, Le: null, ExpectedStatus: 0x9000, CommMode: CommMode.Plain);
    internal readonly static NTagCommand SetConfiguration = new(Name: "SetConfiguration", CLA: 0x90, INS: 0x5C, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: CommMode.Full, CommandHeaderSize: 1);
    internal readonly static NTagCommand ISOUpdateBinary = new(Name: "ISOUpdateBinary", CLA: 0x00, INS: 0xD6, P1: null, P2: null, Lc: null, Data: null, Le: null, ExpectedStatus: 0x9000, CommMode: CommMode.Plain);
    internal readonly static NTagCommand WriteData = new(Name: "WriteData", CLA: 0x90, INS: 0x8D, P1: 0, P2: 0, Lc: null, Data: null, Le: 0, ExpectedStatus: 0x9100, CommMode: null, CommandHeaderSize: 7);
}
