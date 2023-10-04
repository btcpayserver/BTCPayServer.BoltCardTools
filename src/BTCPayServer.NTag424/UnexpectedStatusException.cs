using System;

namespace BTCPayServer.NTag424;

public class UnexpectedResponseException : Exception
{
    public UnexpectedResponseException(string? message) : base(message)
    {

    }
}
public class UnexpectedStatusException : UnexpectedResponseException
{
    public UnexpectedStatusException(string commandName, int expectedStatus, NTagError error)
        : base($"Error for {commandName}: Expected {expectedStatus:X4}, Actual: {error}")
    {
        Details = error;
    }
    public NTagError? Details { get; }
    public UnexpectedStatusException(string commandName, int expectedStatus, int actualStatus)
        : base($"Unexpected status for {commandName}: Expected: {expectedStatus:X4}, Actual: {actualStatus:X4}")
    {
    }
}
