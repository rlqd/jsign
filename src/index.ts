
export interface Message {
    payload: string,
    timestamp: number,
    signature: string,
}

const utf8Encoder = new TextEncoder();

function getAsciiBytes(data: string) {
    const buf = new Uint8Array(data.length);
    for (let i = 0; i < data.length; ++i) {
        buf[i] = data.charCodeAt(i);
    }
    return buf;
}

export async function generateKey(algorithm: string = "SHA-256") {
    const hmacKey = await crypto.subtle.generateKey(
        {
            name: "HMAC",
            hash: { name: algorithm },
        },
        true,
        ["verify"],
    );
    const key = await crypto.subtle.exportKey('jwk', hmacKey);
    if (key.kty !== 'oct') {
        throw new Error('Unexpected format');
    }
    return key.k!;
}

export async function importKey(key: string, algorithm: string = "SHA-256", verifyOnly: boolean = false) {
    if (typeof key === 'undefined') {
        throw new Error('Key is not set');
    }
    return await crypto.subtle.importKey(
        'jwk',
        {kty: 'oct', k: key},
        { name: "HMAC", hash: { name: algorithm } },
        false,
        verifyOnly ? ["verify"] : ["sign", "verify"],
    );
}

export async function sign(key: CryptoKey, payload: any): Promise<Message>;
export async function sign(key: string, payload: any, algorithm?: string): Promise<Message>;
export async function sign(key: string|CryptoKey, payload: any, algorithm?: string): Promise<Message> {
    algorithm ??= 'SHA-256';

    if (typeof key === 'undefined') {
        throw new Error('Key is not set');
    } else if (typeof key === 'string') {
        key = await importKey(key, algorithm);
    }
    const timestamp = Date.now();
    const payloadStr = JSON.stringify(payload);
    const signature = await crypto.subtle.sign(
        { name: "HMAC" },
        key,
        utf8Encoder.encode(`${payloadStr}|${timestamp}`),
    );
    const signatureStr = typeof Buffer !== 'undefined'
        ? Buffer.from(signature).toString('base64')
        : btoa(String.fromCharCode(...new Uint8Array(signature)));
    return {
        payload: payloadStr,
        timestamp,
        signature: signatureStr,
    };
}

export async function verify<T = any>(key: CryptoKey, message: Message, messageTtl?: number): Promise<T>
export async function verify<T = any>(key: string, message: Message, messageTtl?: number, algorithm?: string): Promise<T>
export async function verify<T = any>(key: string|CryptoKey, message: Message, messageTtl?: number, algorithm?: string): Promise<T> {
    algorithm ??= 'SHA-256';
    messageTtl ??= 10000;

    if (typeof key === 'undefined') {
        throw new Error('Key is not set');
    } else if (typeof key === 'string') {
        key = await importKey(key, algorithm, true);
    }
    if (!message || typeof message.payload !== 'string' || typeof message.timestamp !== 'number' || typeof message.signature !== 'string') {
        throw new Error('Incorrect message');
    }
    if (messageTtl > 0 && (Date.now() - message.timestamp) > messageTtl) {
        throw new Error('Message timestamp expired');
    }
    const signature = typeof Buffer !== 'undefined'
        ? Buffer.from(message.signature, 'base64')
        : getAsciiBytes(atob(message.signature));
    const isValid = await crypto.subtle.verify(
        { name: 'HMAC' },
        key,
        signature,
        utf8Encoder.encode(`${message.payload}|${message.timestamp}`),
    );
    if (!isValid) {
        throw new Error('Signature is not valid');
    }
    return JSON.parse(message.payload);
}
