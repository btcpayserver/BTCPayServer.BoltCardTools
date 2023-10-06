# BTCPayServer.BoltCardTools

## Introduction

This repository hosts tools that help with the creation of [Bolt Cards](https://boltcard.org/).

Content:

* [BTCPayServer.NTag424](https://www.nuget.org/packages/BTCPayServer.NTag424) is the base library implementing the NTag424 protocol, this library is platform agnostic.
* [BTCPayServer.NTag424.PCSC](https://www.nuget.org/packages/BTCPayServer.NTag424.PCSC) is a library implementing APDU transport via [PCSC-Sharp](https://github.com/danm-de/pcsc-sharp) for supporting Windows/Linux/Mac.

## Examples

### How to read the UID of an NTag 424 smart card

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
var ntag = ctx.CreateNTag424();
var key = new AESKey(new byte[16]);
await ntag.AuthenticateEV2First(0, key);

var id = await ntag.GetCardUID();
var idStr = Convert.ToHexString(id, 0, id.Length).ToLowerInvariant();
Console.WriteLine($"Card UID: {idStr}");
```

### How to read the NDEF message of an NTag 424 smart card

```csharp
using BTCPayServer.NTag424.PCSC;
using System;
using NdefLibrary.Ndef;

using var ctx = PCSCContext.Create();
var ntag = ctx.CreateNTag424();
var message = await ntag.ReadNDef();
var uri = new NdefUriRecord(message[0]).Uri;
Console.WriteLine($"Card URI: {uri}");
```

### How to verify the signature of an NTag 424 smart card

BoltCards involve the cooperation of three types of agents:
* `Card Issuer`: This agent configures the cards for lightning payments. This includes setting up the card to use a specific `LNUrl Withdraw Service` and generating the access keys.
* `Payment processor`: This agent reads the card and forwards the payment request to the `LNUrl Withdraw Service`.
* `LNUrl Withdraw Service`: This service authenticates the card and completes the payment.

BoltCards setup involves three different type of access keys:
* The `IssuerKey`: Owned by the `Card Issuer`, this key is used to configure the card.
* The `EncryptionKey`: This key can either be unique to each card or shared among multiple cards. It must be known by the `LNUrl Withdraw Service`.
* The `AuthenticationKey`: This key should be unique and is used to authenticate the card. It must also be known by the `LNUrl Withdraw Service`.

If you are the `LNURL Withdraw Service`, here how to authenticate the card:

```csharp
using BTCPayServer.NTag424;
using BTCPayServer.NTag424.PCSC;
using System;
using System.Collections;
using NdefLibrary.Ndef;

// Set keys have you have setup the card
var encryptionKey = AESKey.Default;

using var ctx = PCSCContext.Create();
var ntag = ctx.CreateNTag424();
var message = await ntag.ReadNDef();
var uri = new NdefUriRecord(message[0]).Uri;
var p = Regex.Match(uri, "p=(.*?)&").Groups[1].Value;
var c = Regex.Match(uri, "c=(.*)").Groups[1].Value;

var piccData = PICCData.Create(encryptionKey.Decrypt(p));

// Note that the `piccData.Uid` contains the UID of the card which can be used to fetch
// the proper real `authenticationKey` of the card.
var authenticationKey = AESKey.Default;

var expectedMac = authenticationKey.GetSunMac(piccData);
var expectedMacStr = Convert.ToHexString(expectedMac, 0, expectedMac.Length);

var actualMacStr = c;
if (expectedMacStr != c)
{
    throw new Exception("Invalid card");
}

// The LNUrlw service should also check `piccData.Counter` is always increasing between payments to avoid replay attacks.
```

### How to setup a bolt card

```csharp
using BTCPayServer.NTag424;
using BTCPayServer.NTag424.PCSC;
using System;
using System.Collections;

using var ctx = PCSCContext.Create();
var ntag = ctx.CreateNTag424();

// Example with hard coded keys
var keys = new BoltcardKeys(
    IssuerKey: new AESKey("00000000000000000000000000000001".HexToBytes()),
    EncryptionKey: new AESKey("00000000000000000000000000000002".HexToBytes()),
    AuthenticationKey: new AESKey("00000000000000000000000000000002".HexToBytes()));
var lnurlwService = "lnurlw://test.com";

// Note `BoltcardKeys.Default` assumes the card hasn't been setup yet.
// If it was not the case, you would need to provide the access keys you provided during the last setup.
await ntag.SetupBoltcard(lnurlwService, BoltcardKeys.Default, keys);

// You can reset the card to its factory state with `await ntag.ResetCard(keys);`
```

## License

MIT
