namespace BoltCardTools;

public record NtagResponse(byte[] Data, ushort sw1sw2)
{
    internal NtagResponse Decode(Ntag424.Session currentSession, CommMode commMode)
    {
        return this with
        {
            Data = currentSession.DecryptResponse((byte)sw1sw2, Data, commMode)
        };
    }
}
