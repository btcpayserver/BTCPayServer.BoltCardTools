using PCSC.Iso7816;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BoltCardTools
{
	public interface IAPDUTransport
	{
		Task<NtagResponse> SendAPDU(NTagCommand apdu);
	}
}
