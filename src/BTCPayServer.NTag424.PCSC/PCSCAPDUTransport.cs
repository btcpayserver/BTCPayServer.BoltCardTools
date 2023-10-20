using System.Buffers;
using PCSC;
using PCSC.Extensions;

namespace BTCPayServer.NTag424.PCSC;

public class PCSCAPDUTransport : IAPDUTransport
{
    public readonly ISCardReader CardReader;
    public PCSCAPDUTransport(ISCardReader cardReader)
    {
        ArgumentNullException.ThrowIfNull(cardReader);
        CardReader = cardReader;
    }

    public Task<NtagResponse> SendAPDU(byte[] apdu)
    {
        return Task.Factory.StartNew(() =>
        {
            var resp = ArrayPool<byte>.Shared.Rent(512);
            try
            {
                int received = resp.Length;
                var sc = CardReader.Transmit(apdu, resp, ref received);
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
