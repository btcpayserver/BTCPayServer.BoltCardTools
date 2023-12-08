using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using PCSC;
using PCSC.Exceptions;
using PCSC.Extensions;

namespace BTCPayServer.NTag424.PCSC;
internal static class Extensions
{
    public static void ThrowEx(this SCardError sc)
    {
        try
        {
            sc.Throw();
        }
        catch (NullReferenceException)
        {
            throw new PCSCException(sc, $"Unknown PCSC error: {(int)sc}");
        }
        throw new PCSCException(sc);
    }
}
