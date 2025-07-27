import { describe, it, before, after } from 'node:test';
import * as assert from 'node:assert/strict';
import * as jsign from '../src';

const BufferOrig = Buffer;
for (const mode of ['Buffer', 'Web']) {

describe(`jsign (${mode})`, () => {

    before(() => {
        if (mode === 'Web') {
            Buffer = undefined as any;
        }
    });

    after(() => {
        Buffer = BufferOrig;
    });

    it('generateKey(): creates key with default algorithm', async () => {
        const key = await jsign.generateKey();
        assert.match(key, /^[\w-]{86}$/);
    });

    it('generateKey(): creates key with specified algorithm', async () => {
        const key = await jsign.generateKey('SHA-512');
        assert.match(key, /^[\w-]{171}$/);
    });

    it('generateKey(): creates key with specified algorithm', async () => {
        const key = await jsign.generateKey('SHA-512');
        assert.match(key, /^[\w-]{171}$/);
    });

    it('generateKey(): creates key with incorrect algorithm', async () => {
        try {
            await jsign.generateKey('something');
            assert.fail('Must not succeed');
        } catch {}
    });

    it('importKey(): imports key with default algorithm', async () => {
        const key = await jsign.importKey('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw');
        assert.equal(key.algorithm.name, 'HMAC');
        assert.equal((key as any).algorithm.hash?.name, 'SHA-256');
        assert.deepEqual(key.usages, ['sign', 'verify']);
    });

    it('importKey(): imports key with specified algorithm', async () => {
        const key = await jsign.importKey('Y3GTyvx_l8QlWOnZwhFNfm1i5NKCK1Rf3koLrpskJVjEA0io4tPD47oZgnTNtP3risEBtfMWxbUO3Qfa2Q5RDpHqqzLj1y6oAY8zoLMuZAJW6jYsjEb-tNCtd_nqztctqUEfzuzibXwDEi6CAGsSBGy0RLMMEjg6MfKSOTDa1b8', 'SHA-512');
        assert.equal(key.algorithm.name, 'HMAC');
        assert.equal((key as any).algorithm.hash?.name, 'SHA-512');
        assert.deepEqual(key.usages, ['sign', 'verify']);
    });

    it('importKey(): imports key for verify only', async () => {
        const key = await jsign.importKey('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', 'SHA-256', true);
        assert.deepEqual(key.usages, ['verify']);
    });

    it('importKey(): imported key too short', async () => {
        try {
            await jsign.importKey('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', 'SHA-512');
            assert.fail('Must not succeed');
        } catch {}
    });

    it('importKey(): imported key too long', async () => {
        try {
            await jsign.importKey('Y3GTyvx_l8QlWOnZwhFNfm1i5NKCK1Rf3koLrpskJVjEA0io4tPD47oZgnTNtP3risEBtfMWxbUO3Qfa2Q5RDpHqqzLj1y6oAY8zoLMuZAJW6jYsjEb-tNCtd_nqztctqUEfzuzibXwDEi6CAGsSBGy0RLMMEjg6MfKSOTDa1b8', 'SHA-256');
            assert.fail('Must not succeed');
        } catch {}
    });

    it('importKey(): imported key incorrectly encoded', async () => {
        try {
            await jsign.importKey('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcC/"/sO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', 'SHA-256');
            assert.fail('Must not succeed');
        } catch {}
    });

    it('sign(),verify(): sign and verify with string key', async () => {
        const originalData = {hello: 'World'};
        const message = await jsign.sign('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', originalData);
        const data = await jsign.verify('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', message);
        assert.deepEqual(data, originalData);
    });

    it('sign(),verify(): sign and verify with string key of specified algorithm', async () => {
        const key = 'Y3GTyvx_l8QlWOnZwhFNfm1i5NKCK1Rf3koLrpskJVjEA0io4tPD47oZgnTNtP3risEBtfMWxbUO3Qfa2Q5RDpHqqzLj1y6oAY8zoLMuZAJW6jYsjEb-tNCtd_nqztctqUEfzuzibXwDEi6CAGsSBGy0RLMMEjg6MfKSOTDa1b8';
        const originalData = {hello: 'World'};
        const message = await jsign.sign(key, originalData, 'SHA-512');
        const data = await jsign.verify(key, message, 10000, 'SHA-512');
        assert.deepEqual(data, originalData);
    });

    it('sign(),verify(): sign and verify with imported key', async () => {
        const key = await jsign.importKey('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw');
        const originalData = {hello: 'World'};
        const message = await jsign.sign(key, originalData);
        const data = await jsign.verify(key, message);
        assert.deepEqual(data, originalData);
    });

    it('sign(),verify(): sign and verify with imported key of specified algorithm', async () => {
        const key = await jsign.importKey('Y3GTyvx_l8QlWOnZwhFNfm1i5NKCK1Rf3koLrpskJVjEA0io4tPD47oZgnTNtP3risEBtfMWxbUO3Qfa2Q5RDpHqqzLj1y6oAY8zoLMuZAJW6jYsjEb-tNCtd_nqztctqUEfzuzibXwDEi6CAGsSBGy0RLMMEjg6MfKSOTDa1b8', 'SHA-512');
        const originalData = {hello: 'World'};
        const message = await jsign.sign(key, originalData);
        const data = await jsign.verify(key, message, 10000);
        assert.deepEqual(data, originalData);
    });

    it('verify(): fails to verify with old timestamp', async () => {
        const message = await jsign.sign('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', {hello: 'World'});
        message.timestamp = Date.now() - 100000;
        try {
            await jsign.verify('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', message);
            assert.fail('Must not succeed');
        } catch (e: any) {
            assert.equal(e.message, 'Message timestamp expired');
        }
    });

    it('verify(): allows old timestamp with negative ttl', async () => {
        const message = await jsign.sign('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', {hello: 'World'});
        message.timestamp = Date.now() - 100000;
        try {
            await jsign.verify('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', message, -1);
            assert.fail('Must not succeed');
        } catch (e: any) {
            // Also tests that it fails if timestamp was tampered with
            assert.equal(e.message, 'Signature is not valid');
        }
    });

    it('verify(): fails to verify with incorrect signature', async () => {
        const message = await jsign.sign('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', {hello: 'World'});
        message.signature = 'vBqECKzjGWwJ/qGutMcdaXPswapj84OTfB+e04m9mw0=';
        try {
            await jsign.verify('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', message);
            assert.fail('Must not succeed');
        } catch (e: any) {
            assert.equal(e.message, 'Signature is not valid');
        }
    });

    it('verify(): fails to verify with tampered payload', async () => {
        const message = await jsign.sign('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', {hello: 'World'});
        message.payload = 'Something else';
        try {
            await jsign.verify('b0vb9oCsM1n9z6qkkGoSdFps_S6VNcCFDOsO3mHtvEbyfVgxEoND0TNCD8VOSE70six7VZhOxHYe8QgIhs_2Yw', message);
            assert.fail('Must not succeed');
        } catch (e: any) {
            assert.equal(e.message, 'Signature is not valid');
        }
    });
});

}