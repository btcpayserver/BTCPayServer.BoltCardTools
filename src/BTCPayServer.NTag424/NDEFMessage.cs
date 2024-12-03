using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using NdefLibrary.Ndef;

namespace BTCPayServer.NTag424;
public class NDEFMessage
{
    internal readonly NdefMessage _Message;
    public bool IsEmpty => _Message.Count == 0;

    public NDEFMessage(byte[] bytes)
    {
        ArgumentNullException.ThrowIfNull(bytes);
        _Message = NdefLibrary.Ndef.NdefMessage.FromByteArray(bytes);
    }
    internal NDEFMessage(NdefMessage message)
    {
        _Message = message;
    }
    public byte[] ToBytes() => _Message.ToByteArray();
}
