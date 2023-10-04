
using System;

namespace BoltCardTools;

public record PICCData(byte[]? Uid, int? Counter)
{
	public static PICCData Create(ReadOnlySpan<byte> data)
	{
		bool hasUid = (data[0] & 0b1000_0000) != 0;
		bool hasCounter = (data[0] & 0b0100_0000) != 0;
		if (hasUid && ((data[0] & 0b0000_0111) != 0b0000_0111))
			throw new InvalidOperationException("Invalid PICCData");
		int i = 1;
		byte[]? uid = null;
		int? counter = null;
		if (hasUid)
		{
			uid = data[i..(i + 7)].ToArray();
			i += 7;
		}
		if (hasCounter)
		{
			counter = data[i] | data[i + 1] << 8 | data[i + 2] << 16;
		}
		return new PICCData(uid, counter);
	}
}
