using NdefLibrary.Ndef;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace BoltCardTools
{
	public class BoltCard
	{
        public BoltCard(Ntag424 ntag)
        {
			Ntag = ntag;
		}
		public Ntag424 Ntag { get; }


		private static byte[] CreateNDefMessage(string lnUrl)
		{
			var queryString = "p=00000000000000000000000000000000&c=0000000000000000";
			var templateUrl = lnUrl.Contains("?", StringComparison.OrdinalIgnoreCase) ?
								$"{lnUrl}?{queryString}" :
								$"{lnUrl}&{queryString}";
			var message = new NdefLibrary.Ndef.NdefMessage
			{
				new NdefUriRecord() { Uri = templateUrl }
			};
			return message.ToByteArray();
		}
	}
}
