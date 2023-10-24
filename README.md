# BTCPayServer.BoltCardTools

## Introduction

This repository hosts tools that help with the creation of [Bolt Cards](https://boltcard.org/).

Content:

* [BTCPayServer.NTag424](https://www.nuget.org/packages/BTCPayServer.NTag424) is the base library implementing the NTag424 protocol, this library is platform agnostic.
* [BTCPayServer.NTag424.PCSC](https://www.nuget.org/packages/BTCPayServer.NTag424.PCSC) is a library implementing APDU transport via [PCSC-Sharp](https://github.com/danm-de/pcsc-sharp) for supporting Windows/Linux/Mac.

We tested the following smart card reader:
* [identiv utrust 3700 f](https://www.identiv.com/products/logical-access-control/smart-card-readers-writers/contactless-smart-card-readers-writers/3700f)
* [ACR122U-A9](https://www.acs.com.hk/en/products/3/acr122u-usb-nfc-reader/)

## Examples

### How to read the UID of an NTag 424 smart card

Plug in a smart card reader, and place an NTag 424 smart card on it.

Reference the nuget package [BTCPayServer.NTag424.PCSC](https://www.nuget.org/packages/BTCPayServer.NTag424.PCSC) in your project.

```bash
dotnet add package BTCPayServer.NTag424.PCSC
```

Then to use it:

```csharp
using BTCPayServer.NTag424;
using BTCPayServer.NTag424.PCSC;
using System;

using var ctx = await PCSCContext.WaitForCard();
var ntag = ctx.CreateNTag424();
var key = AESKey.Default;
await ntag.AuthenticateEV2First(0, key);

var id = await ntag.GetCardUID();
var idStr = Convert.ToHexString(id, 0, id.Length).ToLowerInvariant();
Console.WriteLine($"Card UID: {idStr}");
```

### How to read the NDEF message of an NTag 424 smart card

```csharp
using BTCPayServer.NTag424.PCSC;
using System;

using var ctx = await PCSCContext.WaitForCard();
var ntag = ctx.CreateNTag424();
var uri = await ntag.TryReadNDefURI();
Console.WriteLine($"Card URI: {uri}");
```

### How to verify the signature of an NTag 424 smart card

```csharp
using BTCPayServer.NTag424;
using BTCPayServer.NTag424.PCSC;
using System;
using System.Security;
using System.Collections;

using var ctx = await PCSCContext.WaitForCard();
var ntag = ctx.CreateNTag424();
// In prod: var issuerKey = IssuerKey.Random();
var issuerKey = new IssuerKey("00000000000000000000000000000001".HexToBytes());
// In prod: var cardKey = CardKey.Random();
var cardKey = new CardKey("00000000000000000000000000000002".HexToBytes());

// First time authenticate is with the default 00000000000000000000000000000000 key
await ntag.AuthenticateEV2First(0, AESKey.Default);
var uid = await ntag.GetCardUID();

var keys = cardKey.DeriveBoltcardKeys(issuerKey, uid);
await ntag.SetupBoltcard("lnurlw://blahblah.com", BoltcardKeys.Default, keys);

var uri = await ntag.TryReadNDefURI();
var piccData = issuerKey.TryDecrypt(uri);
if (piccData is null)
    throw new SecurityException("Impossible to decrypt with issuerKey");

// In production, you would fetch the card key from database
// var cardKey = await GetCardKey(issuerKey.GetId(piccData.Uid));

if (!cardKey.CheckSunMac(uri, piccData))
    throw new SecurityException("Impossible to decrypt with issuerKey");

await ntag.ResetCard(issuerKey, cardKey);
// If this method didn't throw an exception, it has been successfully decrypted and authenticated.
// You can reset the card with `await ntag.ResetCard(issuerKey, cardKey);`.
```

### How to setup a bolt card

```csharp
using BTCPayServer.NTag424;
using BTCPayServer.NTag424.PCSC;
using System;
using System.Collections;

using var ctx = await PCSCContext.WaitForCard();
var ntag = ctx.CreateNTag424();

// Example with hard coded keys
var keys = new BoltcardKeys(
    AppMasterKey: new AESKey("00000000000000000000000000000001".HexToBytes()),
    EncryptionKey: new AESKey("00000000000000000000000000000002".HexToBytes()),
    AuthenticationKey: new AESKey("00000000000000000000000000000003".HexToBytes()),
    K3: new AESKey("00000000000000000000000000000004".HexToBytes()),
    K4: new AESKey("00000000000000000000000000000005".HexToBytes()));

var lnurlwService = "lnurlw://test.com";

// Note `BoltcardKeys.Default` assumes the card hasn't been setup yet.
// If it was not the case, you would need to provide the access keys you provided during the last setup.
await ntag.SetupBoltcard(lnurlwService, BoltcardKeys.Default, keys);

// You can reset the card to its factory state with `await ntag.ResetCard(keys);`
```

### How to setup a bolt card with deterministic keys, and decrypt the PICCData

[Deterministic keys](https://github.com/boltcard/boltcard/blob/main/docs/DETERMINISTIC.md) simplifies the management of Boltcard by removing the need to store the keys of each Boltcards in a database.

Here is an example of how to setup a card with deterministic keys, and decrypt the PICCData.
```csharp
using var ctx = await PCSCContext.WaitForCard();
var ntag = ctx.CreateNTag424();
var issuerKey = new IssuerKey("00000000000000000000000000000001".HexToBytes());

// First time authenticate is with the default 00.000 key
await ntag.AuthenticateEV2First(0, AESKey.Default);
var uid = await ntag.GetCardUID();

//var nonce = IssuerKey.RandomNonce();
var nonce = new byte[16]; // Please use IssuerKey.RandomNonce() in production

// SaveNonce should be implemented by the server
await SaveNonce(issuerKey.GetId(uid), nonce);

var keys = issuerKey.DeriveBoltcardKeys(uid, nonce);
await ntag.SetupBoltcard("lnurlw://blahblah.com", BoltcardKeys.Default, keys);

var uri = await ntag.TryReadNDefURI();
var piccData = issuerKey.TryDecrypt(uri);
if (piccData == null)
    throw new SecurityException("Impossible to decrypt with issuerKey");

// In real life, you would fetch the nonce from database 
// var nonce = await FetchNonce(issuerKey.GetId(piccData.Uid));

if (!issuerKey.CheckSunMac(uri, piccData, nonce))
    throw new SecurityException("Impossible to check the SUN MAC");

// If this method didn't throw an exception, it has been successfully decrypted and authenticated.
// You can reset the card with `await ntag.ResetCard(issuerKey, nonce);`.
```

## License

MIT
