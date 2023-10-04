using System.Buffers;
using PCSC;
using PCSC.Extensions;

namespace BTCPayServer.NTag424;

public class PCSCAPDUTransport : IAPDUTransport
{
    public readonly ISCardReader CardReader;
    public PCSCAPDUTransport(ISCardReader cardReader)
    {
        ArgumentNullException.ThrowIfNull(cardReader);
        CardReader = cardReader;
    }

    public Task<NtagResponse> SendAPDU(NTagCommand apdu)
    {
        return Task.Factory.StartNew(() =>
        {
            var bytes = apdu.ToBytes();
            var resp = ArrayPool<byte>.Shared.Rent(512);
            try
            {
                int received = resp.Length;
                var sc = CardReader.Transmit(bytes, resp, ref received);
                if (sc != SCardError.Success)
                    sc.Throw();
                var sw1sw2 = (ushort)(resp[received - 2] << 8 | resp[received - 1]);
                var data = resp[..(received - 2)];
                return new NtagResponse(data, sw1sw2);
            }
            finally
            {
                ArrayPool<byte>.Shared.Return(resp);
            }
        }, TaskCreationOptions.LongRunning);
    }
}
