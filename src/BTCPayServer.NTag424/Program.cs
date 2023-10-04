using System.Linq;
using System.Threading.Tasks;
using BoltCardTools;
using NdefLibrary.Ndef;
using PCSC;
using PCSC.Extensions;

// https://github.com/boltcard/boltcard-wallet/blob/master/class/Ntag424.js
// https://github.com/boltcard/boltcard-wallet/blob/master/screen/boltcard/create.js#L201
// https://github.com/danm-de/pcsc-sharp
public class Program
{
    public static async Task Main(string[] args)
    {
        var message = NdefMessage.FromByteArray("D1012C5503746573742E636F6D3F703D303030303030303030303030303026633D303030303030303030303030303030".HexToBytes());

        // http://test.com?p=00000000000000&c=000000000000000, description=, uriType=sms, mirrorFlags=null, mUri=http://test.com?p=00000000000000&c=000000000000000

        var contextFactory = ContextFactory.Instance;
        using var ctx = contextFactory.Establish(SCardScope.System);
        var readerName = ctx.GetReaders().FirstOrDefault();
        if (readerName != null)
        {
            using var reader = new SCardReader(ctx);
            reader.Connect(readerName, SCardShareMode.Exclusive, SCardProtocol.Any).ThrowIfNotSuccess();
            var transport = new PCSCAPDUTransport(reader);
            var ntag = new Ntag424(transport);
            var key = new AESKey(new byte[16]);
            await ntag.AuthenticateEV2First(0, key);
            await ntag.AuthenticateEV2NonFirst(0, key);

            //Console.WriteLine("UID: " + (await ntag.GetCardUID()).ToHex());
            //await ntag.SetupBoltcard("http://test.com");
            //await ntag.ChangeFileSettings();

            //await ntag.ReadFile(DataFile.NDEF, 0, 10);
            //await ntag.WriteNDef(message);
            //await ntag.ReadFile(DataFile.NDEF, 0, 10);
            //await ntag.WriteNDef(message);
            //await ntag.IsoSelectFile(DataFile.CC);
            //var d = await ntag.ReadFile(DataFile.NDEF, 0, 0);
            //Console.WriteLine(d.ToHex());
            //await ntag.GetCardUID
            //var access = await ntag.GetFileSettings();
        }
    }


}
