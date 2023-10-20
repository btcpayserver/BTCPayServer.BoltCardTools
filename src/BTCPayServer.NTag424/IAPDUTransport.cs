using System.Threading;
using System.Threading.Tasks;

namespace BTCPayServer.NTag424;

public interface IAPDUTransport
{
    Task<NtagResponse> SendAPDU(byte[] apdu, CancellationToken cancellationToken);
}
