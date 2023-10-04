# BTCPayServer.BoltCardTools

## Introduction

This repository hosts tools that help with the creation of [Bolt Cards](https://boltcard.org/).

Content:

* [BTCPayServer.NTag424](https://www.nuget.org/packages/BTCPayServer.NTag424) is the base library implementing the NTag424 protocol, this library is platform agnostic.
* [BTCPayServer.NTag424.PCSC](https://www.nuget.org/packages/BTCPayServer.NTag424.PCSC) is a library implementing APDU transport via [PCSC-Sharp](https://github.com/danm-de/pcsc-sharp) for supporting Windows/Linux/Mac.

## Examples

Plug in a smart card reader, such as the [identiv utrust 3700 f](https://www.identiv.com/products/logical-access-control/smart-card-readers-writers/contactless-smart-card-readers-writers/3700f), and place an NTag 424 smart card on it.

Reference the nuget package [BTCPayServer.NTag424.PCSC](https://www.nuget.org/packages/BTCPayServer.NTag424.PCSC) in your project.

```bash
dotnet add package BTCPayServer.NTag424.PCSC
```

Then to use it:

```csharp
using BTCPayServer.NTag424.PCSC;
using System;

using var ctx = PCSCContext.Create();
var ntag424 = ctx.CreateNTag424();
var key = new AESKey(new byte[16]);
await ntag.AuthenticateEV2First(0, key);

var id = await ntag.GetCardUID();
var idStr = Convert.ToHexString(id, 0, id.Length).ToLowerInvariant();
Console.WriteLine($"Card UID: {idStr}");
```

## License

MIT
