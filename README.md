# jsign

Webcrypto-based Javascript/Typescript library for HMAC signing and validation of JSON data.
Compatible with Deno/Cloudflare/Convex environments, which don't have nodejs crypto module and buffers.

Can be used to secure webhooks or APIs.

```
npm i jsign
```

## Generate key

By default, SHA-256 key is generated.

If using SHA-512, algorithm parameter must also be specified in `sign`/`verify` or `importKey` methods.

```typescript
import * as jsign from 'jsign';

const key = await jsign.generateKey(); // Default is SHA-256
console.log(key); // '9pw6u05Eyi59nAQuZ_fubriRvp05FarO0ACxgCOYvjBBkXd0-ggPXoKiW57DN75NpE2RZIX8sgIQQk38t6efmg'

const longerKey = await jsign.generateKey('SHA-512');
console.log(key); // 'xjdsLbqBVnrsuJLa1IdhJg2HWpRyUuFVGYTrbD1ta69eAs35rAKNF1rNjDqEfW8VsqXI4ExdkT-7GKJvwBu7BabMSVncfQaIcVo3-nzQPtvYaxc2gsgmkyeJlY-TEKEM3IzqSPGyrdwJhBhduZ_yGh8ymr8Mvx_CUjWyDdWRVEs'
```

## Sign data

Sign method returns an object, which can be JSON-encoded and sent over network to be verified by the recipient.

```typescript
import * as jsign from 'jsign';

const message = await jsign.sign('9pw6u05Eyi59nAQuZ_fubriRvp05FarO0ACxgCOYvjBBkXd0-ggPXoKiW57DN75NpE2RZIX8sgIQQk38t6efmg', {text: 'Hello, World!'});
console.log(message);
// prints:
{
  payload: '{"text":"Hello, World!"}',
  timestamp: 1753632596854,
  signature: 'F8dGz78dx/+7ihYJ0mZCUgBqDJfcsG68jgBfNaPrLeI='
}
```

Or import the key first if you have long-running process

```typescript
import * as jsign from 'jsign';

const key = await jsign.importKey('9pw6u05Eyi59nAQuZ_fubriRvp05FarO0ACxgCOYvjBBkXd0-ggPXoKiW57DN75NpE2RZIX8sgIQQk38t6efmg');
const message = await jsign.sign(key, {text: 'Hello, World!'});
```

## Verify data

Verify data integrity on the recipient side, using the same key.

By default, message ttl is set to 10000ms. If more time has passed between signinig and verifying, it will fail.
This behaviour can be configured with `messageTtl` parameter or disabled if set to `-1`.

```typescript
import * as jsign from 'jsign';

// Optionally, specify your type as a generic to `verify` method to get type-safe result.
interface MyData {
    text: string;
}

const message: jsign.Message = ...;

// will throw an error if something is wrong
const data = await jsign.verify<MyData>('9pw6u05Eyi59nAQuZ_fubriRvp05FarO0ACxgCOYvjBBkXd0-ggPXoKiW57DN75NpE2RZIX8sgIQQk38t6efmg', message);

// data can be trusted now
console.log(data.text); // Hello, World!
```
