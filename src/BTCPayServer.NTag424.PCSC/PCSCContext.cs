using System.Runtime.CompilerServices;
using PCSC;
using PCSC.Extensions;

namespace BTCPayServer.NTag424.PCSC;
public record PCSCContext(ISCardReader CardReader, ISCardContext Context) : IDisposable
{
    public static PCSCContext Create(string? readerName = null)
    {
        var contextFactory = ContextFactory.Instance;
        var context = contextFactory.Establish(SCardScope.System);
        if (readerName is null)
        {
            readerName = context.GetReaders().FirstOrDefault();
            if (readerName is null)
            {
                throw new InvalidOperationException("No readers found");
            }
        }
        else
        {
            if (!context.GetReaders().Contains(readerName))
                throw new InvalidOperationException("This reader isn't found in the list");
        }
        var reader = new SCardReader(context);
        reader.Connect(readerName, SCardShareMode.Shared, SCardProtocol.Any);
        return new PCSCContext(reader, context);
    }

    public static Task<PCSCContext> WaitForCard(CancellationToken cancellationToken = default)
    {
        return Task.Factory.StartNew(() =>
        {
            var contextFactory = ContextFactory.Instance;
            ISCardContext? context = null;
            IDisposable? registration = null;
createContext:
            context?.Dispose();
            context = contextFactory.Establish(SCardScope.System);
            registration = cancellationToken.Register(() => context.Cancel());
            try
            {
rescanReaders:
                var readerStates = context.GetReaders()
                                        .Select(r => new SCardReaderState()
                                        {
                                            ReaderName = r,
                                            CurrentState = SCRState.Unaware
                                        }).ToArray();

                // No smart card reader, wait for one
                if (readerStates.Length == 0)
                {
                    readerStates = new[]
                    {
                        new SCardReaderState()
                        {
                            ReaderName = "\\\\?PnP?\\Notification",
                            CurrentState = SCRState.Unaware
                        }
                    };
                    var res2 = context.GetStatusChange(IntPtr.Zero, readerStates);
                    for (int i = 0; i < readerStates.Length; i++)
                    {
                        readerStates[i].CurrentStateValue = readerStates[i].EventStateValue;
                    }
                    res2 = context.GetStatusChange(SCardContext.INFINITE, readerStates);
                    if (res2 == SCardError.Cancelled)
                        throw new OperationCanceledException(cancellationToken);
                    if (res2.HasFlag(SCardError.Shutdown))
                        goto createContext;
                    goto rescanReaders;
                }
                IntPtr timeout = IntPtr.Zero;
waitStateChange:
                var res = context.GetStatusChange(timeout, readerStates);
                timeout = SCardContext.INFINITE;
                for (int i = 0; i < readerStates.Length; i++)
                {
                    readerStates[i].CurrentStateValue = readerStates[i].EventStateValue;
                }
                if (res == SCardError.Cancelled)
                    throw new OperationCanceledException(cancellationToken);
                if (res == SCardError.UnknownReader)
                    goto rescanReaders;
                if (res.HasFlag(SCardError.Shutdown))
                    goto createContext;
                if (res == SCardError.Success)
                {
                    var readerName = readerStates.Where(r => r.EventState.CardIsPresent())
                                                 .Select(r => r.ReaderName)
                                                 .FirstOrDefault();
                    if (readerName is not null)
                    {
                        var reader = new SCardReader(context);
                        res = reader.Connect(readerName, SCardShareMode.Shared, SCardProtocol.Any);
                        if (res == SCardError.Success)
                            return new PCSCContext(reader, context);
                        goto rescanReaders;
                    }
                }
                goto waitStateChange;
            }
            catch
            {
                context?.Dispose();
                throw;
            }
            finally
            {
                registration?.Dispose();
            }
        }, TaskCreationOptions.LongRunning);
    }

    public Task WaitForDisconnected(CancellationToken cancellationToken = default)
    {
        return Task.Factory.StartNew(() =>
        {
            using var registration = cancellationToken.Register(() => Context.Cancel());
            IntPtr timeout = IntPtr.Zero;
            var readerStates = new[] 
            {
                new SCardReaderState()
                {
                    ReaderName = CardReader.ReaderName,
                    CurrentState = SCRState.Unaware
                }
            };
waitStateChange:
            var res = Context.GetStatusChange(timeout, readerStates);
            timeout = SCardContext.INFINITE;
            readerStates[0].CurrentStateValue = readerStates[0].EventStateValue;
            if (res == SCardError.Cancelled)
                throw new OperationCanceledException(cancellationToken);
            if (res != SCardError.Success)
                return;
            if (readerStates[0].EventState.CardIsAbsent())
                return;
            goto waitStateChange;
        }, TaskCreationOptions.LongRunning);
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
