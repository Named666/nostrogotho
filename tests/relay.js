/**
 * Shared helpers for the nostrogotho Node.js integration tests.
 *
 * - Spawns the relay binary (build/main.exe on Windows, build/main elsewhere)
 *   with drained stdio so --debug chatter can never stall it.
 * - Queued WebSocket receiver: every inbound frame is kept, so (unlike the
 *   old Python harness whose send() swallowed the next frame) no EOSE/OK can
 *   be lost between a send and a waitFor.
 * - nostr-tools based signing (replaces pynostr).
 */
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';
import {
  generateSecretKey,
  getPublicKey,
  finalizeEvent,
} from 'nostr-tools/pure';

export const ROOT = path.resolve(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
);
export const RELAY_EXE = path.join(
  ROOT,
  'build',
  process.platform === 'win32' ? 'main.exe' : 'main',
);

// Same deterministic test key the Python suite used (secp256k1 privkey 1).
export const TEST_SK_HEX =
  '0000000000000000000000000000000000000000000000000000000000000001';

export function skFromHex(hex) {
  return Uint8Array.from(Buffer.from(hex, 'hex'));
}

export function testSecretKey() {
  return skFromHex(TEST_SK_HEX);
}

export function randomSecretKey() {
  return generateSecretKey();
}

export function pubkeyOf(sk) {
  return getPublicKey(sk);
}

export const TEST_PUBKEY = pubkeyOf(testSecretKey());

export function signEvent(sk, { kind, tags = [], content = '', created_at }) {
  return finalizeEvent(
    {
      kind,
      tags,
      content,
      created_at: created_at ?? Math.floor(Date.now() / 1000),
    },
    sk,
  );
}

/** Build (but do not send) a NIP-42 AUTH event for a challenge. */
export function authEvent(sk, wsUrl, challenge, relayTag) {
  return signEvent(sk, {
    kind: 22242,
    content: '',
    tags: [
      ['relay', relayTag ?? wsUrl],
      ['challenge', challenge],
    ],
  });
}

export function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** A WebSocket with a permanent inbound queue. */
export class Conn {
  constructor(ws, url) {
    this.ws = ws;
    this.url = url;
    this.queue = [];
    this.waiter = null;
    this.closed = false;
    ws.on('message', (data) => {
      let msg;
      try {
        msg = JSON.parse(data.toString());
      } catch {
        return;
      }
      if (this.waiter) {
        const w = this.waiter;
        this.waiter = null;
        w.resolve(msg);
      } else {
        this.queue.push(msg);
      }
    });
    ws.on('close', () => {
      this.closed = true;
      if (this.waiter) {
        const w = this.waiter;
        this.waiter = null;
        w.resolve(null);
      }
    });
  }

  static async open(url, timeout = 5000) {
    const ws = new WebSocket(url);
    // Attach the queue BEFORE the connection completes: the relay sends
    // its AUTH challenge immediately on open and it must not be missed.
    const conn = new Conn(ws, url);
    await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        reject(new Error(`connect timeout: ${url}`));
      }, timeout);
      ws.once('open', () => {
        clearTimeout(timer);
        resolve();
      });
      ws.once('error', (err) => {
        clearTimeout(timer);
        reject(err);
      });
    });
    return conn;
  }

  sendJson(value) {
    this.ws.send(JSON.stringify(value));
  }

  /** Next inbound frame (queue first), or null on close/timeout. */
  async next(timeout = 5000) {
    if (this.queue.length > 0) return this.queue.shift();
    if (this.closed) return null;
    return new Promise((resolve) => {
      const timer = setTimeout(() => {
        if (this.waiter) this.waiter = null;
        resolve(null);
      }, timeout);
      this.waiter = {
        resolve: (msg) => {
          clearTimeout(timer);
          resolve(msg);
        },
      };
    });
  }

  /**
   * Wait for a frame matching `pred` (message-type string, or predicate fn).
   * Non-matching frames are retained for later waits. Throws on timeout.
   */
  async waitFor(pred, timeout = 5000, what = 'message') {
    const match =
      typeof pred === 'function' ? pred : (m) => Array.isArray(m) && m[0] === pred;
    const deadline = Date.now() + timeout;
    const stash = [];
    try {
      for (;;) {
        // Drain the queue first.
        for (let i = 0; i < this.queue.length; i++) {
          if (match(this.queue[i])) {
            const found = this.queue[i];
            this.queue.splice(i, 1);
            this.queue.unshift(...stash.splice(0));
            return found;
          }
        }
        // Move everything currently queued aside, then wait for more.
        stash.push(...this.queue.splice(0));
        const remaining = deadline - Date.now();
        if (remaining <= 0) throw new Error(`Timeout waiting for ${what}`);
        const msg = await this.next(remaining);
        if (msg === null) {
          if (this.closed) throw new Error(`Connection closed waiting for ${what}`);
          throw new Error(`Timeout waiting for ${what}`);
        }
        if (match(msg)) {
          this.queue.unshift(...stash.splice(0));
          return msg;
        }
        stash.push(msg);
      }
    } catch (err) {
      this.queue.unshift(...stash.splice(0));
      throw err;
    }
  }

  async close() {
    if (this.ws.readyState === WebSocket.OPEN) {
      await new Promise((resolve) => {
        this.ws.once('close', resolve);
        this.ws.close();
        setTimeout(resolve, 1000);
      });
    }
  }
}

export class Relay {
  constructor(port) {
    this.port = port;
    this.wsUrl = `ws://127.0.0.1:${port}`;
    this.dbPath = path.join(ROOT, `test_nostrogotho_${port}.sqlite`);
    this.proc = null;
    this.conns = new Set();
  }

  static checkBinary() {
    if (!fs.existsSync(RELAY_EXE)) {
      throw new Error(`Relay not found at ${RELAY_EXE} — build it first (nob win)`);
    }
  }

  async start(extraArgs = [], envOverrides = {}) {
    Relay.checkBinary();
    for (const suffix of ['', '-shm', '-wal', '-journal']) {
      try {
        fs.unlinkSync(this.dbPath + suffix);
      } catch {
        /* ignore */
      }
    }
    const args = [
      '-database',
      this.dbPath,
      '-port',
      String(this.port),
      '-service-url',
      this.wsUrl,
      '--debug',
      ...extraArgs,
    ];
    console.log(`Starting relay: ${RELAY_EXE} ${args.join(' ')}`);
    this.proc = spawn(RELAY_EXE, args, {
      cwd: ROOT,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, ...envOverrides },
    });
    this.proc.stdout.on('data', () => {});
    this.proc.stderr.on('data', () => {});
    this.proc.on('error', (err) => {
      console.error(`relay spawn error: ${err.message}`);
    });
    await sleep(1000);
    if (this.proc.exitCode !== null) {
      throw new Error(`relay exited immediately with code ${this.proc.exitCode}`);
    }
    console.log('Relay started');
  }

  async stop() {
    for (const conn of this.conns) {
      try {
        await conn.close();
      } catch {
        /* ignore */
      }
    }
    this.conns.clear();
    if (this.proc) {
      const proc = this.proc;
      this.proc = null;
      proc.kill();
      await new Promise((resolve) => {
        const timer = setTimeout(resolve, 5000);
        proc.once('exit', () => {
          clearTimeout(timer);
          resolve();
        });
      });
      if (proc.exitCode === null) {
        try {
          proc.kill('SIGKILL');
        } catch {
          /* ignore */
        }
      }
      console.log('Relay stopped');
    }
    for (const suffix of ['', '-shm', '-wal', '-journal']) {
      try {
        fs.unlinkSync(this.dbPath + suffix);
      } catch {
        /* ignore */
      }
    }
  }

  track(conn) {
    this.conns.add(conn);
    return conn;
  }

  async connect() {
    const conn = await Conn.open(this.wsUrl);
    return this.track(conn);
  }

  /**
   * Connect and answer the NIP-42 challenge as `sk`.
   * Returns { conn, ok } where ok is the relay's OK frame (or null when the
   * relay sent no challenge).
   */
  async connectAndAuth(sk) {
    const conn = await this.connect();
    console.log(`Connected to ${this.wsUrl}`);
    const first = await conn.next(3000);
    if (!first || first[0] !== 'AUTH') {
      if (first) conn.queue.unshift(first);
      return { conn, ok: null };
    }
    console.log(`  Received AUTH challenge: ${first[1]}`);
    conn.sendJson(['AUTH', authEvent(sk, this.wsUrl, first[1])]);
    const ok = await conn.waitFor('OK', 5000, 'OK');
    if (ok[2]) {
      console.log('  Authentication successful');
    } else {
      console.log(`  Authentication failed: ${ok[3]}`);
    }
    return { conn, ok };
  }
}

export function assert(cond, message) {
  if (!cond) throw new Error(`assert: ${message}`);
}

/**
 * Run a test function with a relay that is guaranteed to be cleaned up.
 * Handles cleanup even if the test throws or the relay fails to start.
 *
 * @param {number} port - Port for the relay
 * @param {Function} fn - Async function receiving the relay instance
 * @param {string[]} extraArgs - Extra arguments to pass to the relay
 * @param {Object} envOverrides - Environment variable overrides
 * @returns {Promise<any>} Return value of fn
 */
export async function withRelay(port, fn, extraArgs = [], envOverrides = {}) {
  const relay = new Relay(port);
  try {
    await relay.start(extraArgs, envOverrides);
    return await fn(relay);
  } finally {
    await relay.stop();
  }
}

/**
 * Run a test with a relay and an authenticated connection.
 * Guarantees cleanup of both relay and connection.
 *
 * @param {number} port - Port for the relay
 * @param {Function} fn - Async function receiving { relay, conn, ok }
 * @param {Uint8Array} sk - Secret key to authenticate with (default: testSecretKey)
 * @param {string[]} extraArgs - Extra arguments to pass to the relay
 * @param {Object} envOverrides - Environment variable overrides
 * @returns {Promise<any>} Return value of fn
 */
export async function withAuthConn(port, fn, sk = testSecretKey(), extraArgs = [], envOverrides = {}) {
  const relay = new Relay(port);
  try {
    await relay.start(extraArgs, envOverrides);
    const { conn, ok } = await relay.connectAndAuth(sk);
    try {
      return await fn({ relay, conn, ok });
    } finally {
      await conn.close();
    }
  } finally {
    await relay.stop();
  }
}
