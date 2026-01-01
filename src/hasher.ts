// client/src/core/util/hasher.ts

/**
 * Simple wrapper for hashing behavior. Currently supports a streamed approach
 * allowing for reuse of a single instance calling 'init' between uses, or
 * static one off approaches for smaller data.
 *
 * ENVIRONMENT BEHAVIOR:
 * - Browser: Uses native Web Crypto API for SHA-256/SHA-512 (performance),
 *   'hash-wasm' for MD5/BLAKE3/CRC32 and when resumability is required.
 * - Node.js: Uses native 'node:crypto' for SHA256/SHA512/MD5 (speed),
 *   'hash-wasm' for BLAKE3/CRC32 and when resumability is required.
 *
 * RESUMABILITY:
 * To enable save/load state serialization, pass `{ resumable: true }` to the constructor.
 * This forces WASM usage since native crypto APIs don't support state serialization.
 *
 * Using the 'hash-wasm' library for Node and Browser hashing algorithms.
 * Dependencies: 0
 * Source: https://www.npmjs.com/package/hash-wasm
 *
 * Adapted from server/src/transfer-engine/core/util/hasher.ts for client parity.
 */
import {
    md5, crc32, sha256, sha512, blake3,
    createMD5, createCRC32, createSHA256, createSHA512, createBLAKE3
} from 'hash-wasm';
import type { IHasher, IDataType } from 'hash-wasm';

//#region TYPES

export interface IOResult<T> {
    success: boolean;
    message: string;
    data?: T;
}

export const HashMethod = {
    MD5: 'md5',
    SHA256: 'sha256',
    SHA512: 'sha512',
    CRC32: 'crc32',
    BLAKE3: 'blake3',
} as const;

export type HashMethod = typeof HashMethod[keyof typeof HashMethod];

/** Options for creating a Hasher instance. */
export interface HasherOptions {
    /**
     * If true, forces WASM implementation to enable save/load state serialization.
     * Native crypto APIs do not support resumability.
     * @default false
     */
    resumable?: boolean;
}

/** Hash state snapshot for resume support. */
export interface HashStateSnapshot {
    /** Hash method used. */
    method: HashMethod | 'none';
    /** Base64-encoded internal hasher state from hash-wasm save(). */
    state: string;
    /** Number of bytes that have been hashed. */
    bytesHashed: number;
    /** Chunk index after which this snapshot was taken. */
    afterChunkIndex: number;
}

/** Engine type used for hashing. */
export type HashEngine = 'wasm' | 'node-native' | 'web-crypto';

//#endregion

//#region HELPERS

// Environment detection - more robust than just checking process.versions
const isNode = typeof globalThis.process !== 'undefined'
    && globalThis.process.versions != null
    && globalThis.process.versions.node != null
    && typeof globalThis.window === 'undefined';

const isBrowser = typeof globalThis.window !== 'undefined'
    && typeof globalThis.document !== 'undefined';

// Check for Web Crypto API availability
const hasWebCrypto = typeof globalThis.crypto !== 'undefined'
    && typeof globalThis.crypto.subtle !== 'undefined';

// Cached Node crypto module
let nodeCryptoModule: typeof import('node:crypto') | null = null;
let nodeCryptoLoadAttempted = false;

async function getNodeCrypto(): Promise<typeof import('node:crypto') | null> {
    if (nodeCryptoLoadAttempted) return nodeCryptoModule;
    nodeCryptoLoadAttempted = true;

    if (!isNode) return null;

    try {
        nodeCryptoModule = await import('node:crypto');
        return nodeCryptoModule;
    } catch {
        return null;
    }
}

function getErrorString(error: unknown): string {
    if (error instanceof Error) {
        return error.message;
    }
    return String(error);
}

/** Convert Uint8Array to base64 string (works in both Node and browser). */
function uint8ArrayToBase64(bytes: Uint8Array): string {
    if (isNode && typeof Buffer !== 'undefined') {
        return Buffer.from(bytes).toString('base64');
    }
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
        binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary);
}

/** Convert base64 string to Uint8Array (works in both Node and browser). */
function base64ToUint8Array(base64: string): Uint8Array {
    if (isNode && typeof Buffer !== 'undefined') {
        return new Uint8Array(Buffer.from(base64, 'base64'));
    }
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
}

/** Convert Uint8Array to hex string. */
function uint8ArrayToHex(bytes: Uint8Array): string {
    return Array.from(bytes)
        .map(b => b.toString(16).padStart(2, '0'))
        .join('');
}

/** Normalize input data to Uint8Array for Web Crypto API. */
function normalizeToUint8Array(data: IDataType): Uint8Array {
    if (data instanceof Uint8Array) {
        return data;
    }
    if (typeof data === 'string') {
        return new TextEncoder().encode(data);
    }
    if (ArrayBuffer.isView(data)) {
        return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
    }
    // Assume it's an ArrayBuffer or similar
    return new Uint8Array(data as ArrayBuffer);
}

/**
 * Adapter to make Node's native crypto look like hash-wasm IHasher.
 * Note: Does not support save/load (not resumable).
 */
class NodeNativeHasherAdapter implements IHasher {
    private engine: ReturnType<typeof import('node:crypto').createHash> | null = null;
    private cryptoLib: typeof import('node:crypto');
    private algo: string;

    blockSize: number;
    digestSize: number;

    constructor(algo: string, cryptoLib: typeof import('node:crypto')) {
        this.algo = algo;
        this.cryptoLib = cryptoLib;

        // Set appropriate sizes based on algorithm
        switch (algo) {
            case 'md5':
                this.blockSize = 64;
                this.digestSize = 16;
                break;
            case 'sha256':
                this.blockSize = 64;
                this.digestSize = 32;
                break;
            case 'sha512':
                this.blockSize = 128;
                this.digestSize = 64;
                break;
            default:
                this.blockSize = 64;
                this.digestSize = 32;
        }

        this.init();
    }

    init(): IHasher {
        this.engine = this.cryptoLib.createHash(this.algo);
        return this;
    }

    update(data: IDataType): IHasher {
        if (!this.engine) throw new Error('Hasher not initialized');
        // Node crypto accepts Buffer, string, or TypedArray
        if (typeof data === 'string') {
            this.engine.update(data, 'utf8');
        } else {
            this.engine.update(data as Buffer | Uint8Array);
        }
        return this;
    }

    digest(outputType: 'binary'): Uint8Array;
    digest(outputType?: 'hex'): string;
    digest(outputType: 'hex' | 'binary' = 'hex'): string | Uint8Array {
        if (!this.engine) throw new Error('Hasher not initialized');
        if (outputType === 'binary') {
            return new Uint8Array(this.engine.digest());
        }
        return this.engine.digest('hex');
    }

    save(): Uint8Array {
        throw new Error('Node native crypto does not support state saving. Use { resumable: true } option.');
    }

    load(_state: Uint8Array): IHasher {
        throw new Error('Node native crypto does not support state loading. Use { resumable: true } option.');
    }
}

/**
 * Adapter to make browser Web Crypto API look like hash-wasm IHasher.
 * Note: Web Crypto only supports one-shot digest, so we accumulate chunks.
 * Note: Does not support save/load (not resumable).
 */
class WebCryptoHasherAdapter implements IHasher {
    private chunks: Uint8Array[] = [];
    private algo: 'SHA-256' | 'SHA-512';

    blockSize: number;
    digestSize: number;

    constructor(algo: 'SHA-256' | 'SHA-512') {
        this.algo = algo;

        if (algo === 'SHA-256') {
            this.blockSize = 64;
            this.digestSize = 32;
        } else {
            this.blockSize = 128;
            this.digestSize = 64;
        }

        this.init();
    }

    init(): IHasher {
        this.chunks = [];
        return this;
    }

    update(data: IDataType): IHasher {
        this.chunks.push(normalizeToUint8Array(data));
        return this;
    }

    digest(outputType: 'binary'): Uint8Array;
    digest(outputType?: 'hex'): string;
    digest(outputType: 'hex' | 'binary' = 'hex'): string | Uint8Array {
        // Web Crypto is async-only, but IHasher.digest is sync.
        // We need to throw here and use digestAsync instead.
        throw new Error('WebCryptoHasherAdapter.digest() is not supported. Use digestAsync().');
    }

    async digestAsync(format: 'hex' | 'binary' = 'hex'): Promise<string | Uint8Array> {
        // Concatenate all chunks
        const totalLength = this.chunks.reduce((sum, chunk) => sum + chunk.length, 0);
        const combined = new Uint8Array(totalLength);
        let offset = 0;
        for (const chunk of this.chunks) {
            combined.set(chunk, offset);
            offset += chunk.length;
        }

        // Use ArrayBuffer slice to avoid SharedArrayBuffer type issues
        const buffer = combined.buffer.slice(combined.byteOffset, combined.byteOffset + combined.byteLength) as ArrayBuffer;
        const hashBuffer = await globalThis.crypto.subtle.digest(this.algo, buffer);
        const hashArray = new Uint8Array(hashBuffer);

        if (format === 'binary') {
            return hashArray;
        }
        return uint8ArrayToHex(hashArray);
    }

    save(): Uint8Array {
        throw new Error('Web Crypto API does not support state saving. Use { resumable: true } option.');
    }

    load(_state: Uint8Array): IHasher {
        throw new Error('Web Crypto API does not support state loading. Use { resumable: true } option.');
    }
}

//#endregion

//#region HASHER CLASS

export class Hasher {
    public hash: string = '';
    public timeElapsed: number = 0;

    private method: HashMethod = HashMethod.BLAKE3;
    private hasher: IHasher | null = null;
    private webCryptoHasher: WebCryptoHasherAdapter | null = null;
    private timeStart: number = 0;
    private engine: HashEngine = 'wasm';
    private readonly resumable: boolean;

    constructor(method?: HashMethod, options?: HasherOptions) {
        this.method = method ?? this.method;
        this.resumable = options?.resumable ?? false;
    }

    // streaming
    async open(): Promise<IOResult<unknown>> {
        try {
            this.hasher = null;
            this.webCryptoHasher = null;
            this.engine = 'wasm';

            // If resumable is required, skip native implementations
            if (!this.resumable) {
                // 1. Try Node native crypto for supported algorithms
                const nodeNativeSupported: HashMethod[] = [HashMethod.SHA256, HashMethod.SHA512, HashMethod.MD5];

                if (isNode && nodeNativeSupported.includes(this.method)) {
                    const crypto = await getNodeCrypto();
                    if (crypto) {
                        this.hasher = new NodeNativeHasherAdapter(this.method, crypto);
                        this.engine = 'node-native';
                    }
                }

                // 2. Try Web Crypto API in browser for SHA-256/SHA-512
                const webCryptoSupported: HashMethod[] = [HashMethod.SHA256, HashMethod.SHA512];

                if (!this.hasher && isBrowser && hasWebCrypto && webCryptoSupported.includes(this.method)) {
                    const webCryptoAlgo = this.method === HashMethod.SHA256 ? 'SHA-256' : 'SHA-512';
                    this.webCryptoHasher = new WebCryptoHasherAdapter(webCryptoAlgo);
                    this.hasher = this.webCryptoHasher;
                    this.engine = 'web-crypto';
                }
            }

            // 3. Fallback to WASM (always works, supports resumability)
            if (!this.hasher) {
                switch (this.method) {
                    case HashMethod.SHA256:
                        this.hasher = await createSHA256();
                        break;
                    case HashMethod.SHA512:
                        this.hasher = await createSHA512();
                        break;
                    case HashMethod.BLAKE3:
                        this.hasher = await createBLAKE3();
                        break;
                    case HashMethod.CRC32:
                        this.hasher = await createCRC32();
                        break;
                    case HashMethod.MD5:
                        this.hasher = await createMD5();
                        break;
                }
                this.engine = 'wasm';
            }

            if (!this.hasher) {
                throw new Error('Failed to create hasher instance.');
            }

            // initialize
            this.init();

            return {
                success: true,
                message: 'hash open success',
                data: {
                    method: this.method,
                    engine: this.engine,
                    resumable: this.resumable
                }
            };
        } catch (error) {
            return { success: false, message: 'hash open failed', data: { error: getErrorString(error), method: this.method } };
        }
    }

    init(): IOResult<unknown> {
        try {
            if(!this.hasher)
                throw new Error('no hasher created. initialize first.');

            this.hash = '';
            this.hasher.init();
            this.timeElapsed = 0;
            this.timeStart = Date.now();

            return { success: true, message: 'hash init success', data: { method: this.method }};
        } catch(error) {
            return { success: false, message: 'hash init failed', data: { error: getErrorString(error) }};
        }
    }

    update(data: IDataType): IOResult<unknown> {
        try {
            if(!this.hasher)
                throw new Error('no hasher created. initialize first.');

            this.hasher.update(data);
            return { success: true, message: 'hash update success', data: { method: this.method, size: data.length }};
        } catch(error) {
            return { success: false, message: 'hash update failed', data: { error: getErrorString(error) }};
        }
    }

    /**
     * Finalize and get the hash. Use digestAsync() for Web Crypto compatibility.
     * @deprecated Use digestAsync() instead for consistent async behavior.
     */
    digest(): IOResult<unknown> {
        try {
            if (!this.hasher)
                throw new Error('no hasher created. initialize first.');

            if (this.webCryptoHasher) {
                throw new Error('Web Crypto requires async digest. Use digestAsync() instead.');
            }

            this.hash = this.hasher.digest('hex') as string;
            this.timeElapsed = Date.now() - this.timeStart;

            return { success: true, message: 'hash digest success', data: { method: this.method, hash: this.hash, timeElapsed: this.timeElapsed } };
        } catch (error) {
            return { success: false, message: 'hash digest failed', data: { error: getErrorString(error) } };
        }
    }

    /** Finalize and get the hash (async version, works with all engines). */
    async digestAsync(): Promise<IOResult<unknown>> {
        try {
            if (!this.hasher)
                throw new Error('no hasher created. initialize first.');

            if (this.webCryptoHasher) {
                this.hash = await this.webCryptoHasher.digestAsync('hex') as string;
            } else {
                this.hash = this.hasher.digest('hex') as string;
            }
            this.timeElapsed = Date.now() - this.timeStart;

            return { success: true, message: 'hash digest success', data: { method: this.method, hash: this.hash, timeElapsed: this.timeElapsed } };
        } catch (error) {
            return { success: false, message: 'hash digest failed', data: { error: getErrorString(error) } };
        }
    }

    /** Returns the hash method. */
    getMethod(): HashMethod {
        return this.method;
    }

    /** Returns the engine being used ('wasm', 'node-native', or 'web-crypto'). */
    getEngine(): HashEngine {
        return this.engine;
    }

    /** Returns true if this hasher supports save/load state serialization. */
    isResumable(): boolean {
        return this.engine === 'wasm';
    }

    /**
     * Save the current internal hash state for later resumption.
     * Only works when using WASM engine (resumable: true or BLAKE3/CRC32).
     */
    save(): IOResult<{ state: string }> {
        try {
            if (!this.hasher)
                throw new Error('no hasher created. initialize first.');

            if (!this.isResumable()) {
                throw new Error(`Cannot save state with ${this.engine} engine. Create hasher with { resumable: true } option.`);
            }

            const stateBytes = this.hasher.save();
            const base64State = uint8ArrayToBase64(stateBytes);

            return { success: true, message: 'hash state saved', data: { state: base64State } };
        } catch (error) {
            return { success: false, message: 'hash save failed', data: { error: getErrorString(error) } as unknown as { state: string } };
        }
    }

    /**
     * Restore hash state from a previously saved base64-encoded state.
     * Only works when using WASM engine (resumable: true or BLAKE3/CRC32).
     */
    load(base64State: string): IOResult<unknown> {
        try {
            if (!this.hasher)
                throw new Error('no hasher created. initialize first.');

            if (!this.isResumable()) {
                throw new Error(`Cannot load state with ${this.engine} engine. Create hasher with { resumable: true } option.`);
            }

            const stateBytes = base64ToUint8Array(base64State);
            this.hasher.load(stateBytes);

            return { success: true, message: 'hash state loaded', data: { method: this.method } };
        } catch (error) {
            return { success: false, message: 'hash load failed', data: { error: getErrorString(error) } };
        }
    }

    /** Get current hash state snapshot for persistence. */
    getStateSnapshot(bytesHashed: number, afterChunkIndex: number): IOResult<HashStateSnapshot> {
        const saveResult = this.save();
        if (!saveResult.success || !saveResult.data) {
            return { success: false, message: saveResult.message };
        }

        const snapshot: HashStateSnapshot = {
            method: this.method,
            state: saveResult.data.state,
            bytesHashed,
            afterChunkIndex,
        };

        return { success: true, message: 'snapshot created', data: snapshot };
    }

    // static one-offs
    static async hashData(method: HashMethod, data: IDataType): Promise<string> {
        switch (method) {
            case HashMethod.SHA256:
                return Hasher.sha256(data);
            case HashMethod.SHA512:
                return Hasher.sha512(data);
            case HashMethod.BLAKE3:
                return Hasher.blake3(data);
            case HashMethod.CRC32:
                return Hasher.crc32(data);
            case HashMethod.MD5:
                return Hasher.md5(data);
        }
    }

    static async md5(data: IDataType, limit: number = 0): Promise<string> {
        let result: string;

        // Node: use native crypto (cached)
        if (isNode) {
            const crypto = await getNodeCrypto();
            if (crypto) {
                const hash = crypto.createHash('md5');
                if (typeof data === 'string') {
                    hash.update(data, 'utf8');
                } else {
                    hash.update(data as Buffer | Uint8Array);
                }
                result = hash.digest('hex');
            } else {
                result = await md5(data);
            }
        } else {
            // Browser: MD5 not in Web Crypto, use WASM
            result = await md5(data);
        }

        if (limit > 0) return result.substring(0, limit);
        return result;
    }

    static async crc32(data: IDataType, limit: number = 0): Promise<string> {
        // CRC32 only available via WASM
        const result: string = await crc32(data);
        if (limit > 0) return result.substring(0, limit);
        return result;
    }

    static async sha256(data: IDataType, limit: number = 0): Promise<string> {
        let result: string;

        // Node: use native crypto (cached)
        if (isNode) {
            const crypto = await getNodeCrypto();
            if (crypto) {
                const hash = crypto.createHash('sha256');
                if (typeof data === 'string') {
                    hash.update(data, 'utf8');
                } else {
                    hash.update(data as Buffer | Uint8Array);
                }
                result = hash.digest('hex');
            } else {
                result = await sha256(data);
            }
        } else if (hasWebCrypto) {
            // Browser: use Web Crypto API
            const dataBytes = normalizeToUint8Array(data);
            const buffer = dataBytes.buffer.slice(dataBytes.byteOffset, dataBytes.byteOffset + dataBytes.byteLength) as ArrayBuffer;
            const hashBuffer = await globalThis.crypto.subtle.digest('SHA-256', buffer);
            result = uint8ArrayToHex(new Uint8Array(hashBuffer));
        } else {
            // Fallback to WASM
            result = await sha256(data);
        }

        if (limit > 0) return result.substring(0, limit);
        return result;
    }

    static async sha512(data: IDataType, limit: number = 0): Promise<string> {
        let result: string;

        // Node: use native crypto (cached)
        if (isNode) {
            const crypto = await getNodeCrypto();
            if (crypto) {
                const hash = crypto.createHash('sha512');
                if (typeof data === 'string') {
                    hash.update(data, 'utf8');
                } else {
                    hash.update(data as Buffer | Uint8Array);
                }
                result = hash.digest('hex');
            } else {
                result = await sha512(data);
            }
        } else if (hasWebCrypto) {
            // Browser: use Web Crypto API
            const dataBytes = normalizeToUint8Array(data);
            const buffer = dataBytes.buffer.slice(dataBytes.byteOffset, dataBytes.byteOffset + dataBytes.byteLength) as ArrayBuffer;
            const hashBuffer = await globalThis.crypto.subtle.digest('SHA-512', buffer);
            result = uint8ArrayToHex(new Uint8Array(hashBuffer));
        } else {
            // Fallback to WASM
            result = await sha512(data);
        }

        if (limit > 0) return result.substring(0, limit);
        return result;
    }

    static async blake3(data: IDataType, limit: number = 0): Promise<string> {
        // BLAKE3 only available via WASM
        const result: string = await blake3(data);
        if (limit > 0) return result.substring(0, limit);
        return result;
    }
}

//#endregion