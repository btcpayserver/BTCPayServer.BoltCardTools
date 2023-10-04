using System.Threading.Tasks;

namespace BTCPayServer.NTag424;

public interface IAPDUTransport
{
    Task<NtagResponse> SendAPDU(NTagCommand apdu);
}
