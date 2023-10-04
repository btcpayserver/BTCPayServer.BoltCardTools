using PCSC;

namespace BTCPayServer.NTag424.PCSC;
public record PCSCContext(ISCardReader CardReader, ISCardContext Context) : IDisposable
{
    public static PCSCContext Create()
    {
        var contextFactory = ContextFactory.Instance;
        var context = contextFactory.Establish(SCardScope.System);
        var readerNames = context.GetReaders();
        var readerName = readerNames.FirstOrDefault();
        if (readerName is null)
        {
            throw new InvalidOperationException("No readers found");
        }
        var reader = new SCardReader(context);
        reader.Connect(readerName, SCardShareMode.Shared, SCardProtocol.Any);
        return new PCSCContext(reader, context);
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
