using System.Threading.Tasks;

namespace BoltCardTools;

public interface IAPDUTransport
{
    Task<NtagResponse> SendAPDU(NTagCommand apdu);
}
