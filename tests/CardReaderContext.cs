using PCSC;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading.Tasks;

namespace BoltCardTools.Tests
{
	public record CardReaderContext(ISCardReader CardReader, IContextFactory ContextFactory, ISCardContext Context) : IDisposable
	{
		public static CardReaderContext Create()
		{
			var contextFactory = PCSC.ContextFactory.Instance;
			var context = contextFactory.Establish(SCardScope.System);
			var readerNames = context.GetReaders();
			var readerName = readerNames.FirstOrDefault();
			if (readerName is null)
			{
				throw new InvalidOperationException("No readers found");
			}
			var reader = new SCardReader(context);
			reader.Connect(readerName, SCardShareMode.Shared, SCardProtocol.Any);
			return new CardReaderContext(reader, contextFactory, context);
		}
		public void Dispose()
		{
			CardReader.Dispose();
			Context.Dispose();
		}

		public Ntag424 CreateNTag424()
		{
			var transport = new PCSCAPDUTransport(this.CardReader);
			return new Ntag424(transport);
		}
	}
}
