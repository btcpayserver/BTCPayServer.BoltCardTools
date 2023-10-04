using PCSC;
using PCSC.Extensions;
using PCSC.Iso7816;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;

namespace BoltCardTools
{
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
			//return Task.Factory.StartNew(() =>
			//{
			//	var bytes = apdu.ToBytes();
			//	Console.WriteLine(bytes.ToHex());
			//	Console.WriteLine("---");
			//	var resp = new byte[256];
			//	int received = resp.Length;
			//	var sc = CardReader.Transmit(bytes, resp, ref received);
			//	if (sc != SCardError.Success)
			//		sc.Throw();
			//	var sw1sw2 = (ushort)(resp[received - 2] << 8 | resp[received - 1]);
			//	var data = resp[..(received - 2)];
			//	return new NtagResponse(data, sw1sw2);
			//}, TaskCreationOptions.LongRunning);

			var bytes = apdu.ToBytes();
			Console.WriteLine("Command APDU : " + bytes.ToHex());
			var resp = new byte[512];
			int received = resp.Length;
			var sc = CardReader.Transmit(bytes, resp, ref received);
			if (sc != SCardError.Success)
				sc.Throw();
			Console.WriteLine("Response APDU : " + resp[..received].ToHex());
			var sw1sw2 = (ushort)(resp[received - 2] << 8 | resp[received - 1]);
			var data = resp[..(received - 2)];
			return Task.FromResult(new NtagResponse(data, sw1sw2));
		}
	}
}
