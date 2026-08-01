/**
 * amp-buzz — turn Amp into a buzz:// client.
 *
 * Every Amp thread is mirrored to a private channel on your Buzz relay:
 * your prompts publish under your key, the assistant's replies publish
 * under a dedicated agent key carrying a NIP-OA owner attestation, and
 * messages from remote collaborators are injected as context on your
 * next turn (never auto-dispatching a turn).
 *
 * Install: copy this file to ~/.config/amp/plugins/buzz.ts and set
 * BUZZ_RELAY_URL + BUZZ_PRIVATE_KEY (or write them to
 * ~/.config/amp-buzz/config.json). Relay traffic goes through the
 * `buzz` CLI; this file only does key generation and attestation.
 */
import type {
	AgentEndEvent,
	AgentStartEvent,
	PluginAPI,
	ThreadMessage,
} from '@ampcode/plugin'
import { createHash, randomBytes } from 'node:crypto'
import { execFileSync } from 'node:child_process'
import * as fs from 'node:fs'
import * as os from 'node:os'
import * as path from 'node:path'

// ---------------------------------------------------------------------------
// secp256k1 / BIP-340 Schnorr / bech32 — dependency-free, used only for
// one-time agent identity setup. All relay traffic is signed by the buzz CLI.
// ---------------------------------------------------------------------------

const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn
const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n
const GX = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n
const GY = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n

type Point = { x: bigint; y: bigint } | null

export const sha256 = (buf: Buffer): Buffer => createHash('sha256').update(buf).digest()

function mod(a: bigint, m: bigint): bigint {
	const r = a % m
	return r >= 0n ? r : r + m
}

function modInv(a: bigint, m: bigint): bigint {
	let [oldR, r] = [mod(a, m), m]
	let [oldS, s] = [1n, 0n]
	while (r !== 0n) {
		const q = oldR / r
		;[oldR, r] = [r, oldR - q * r]
		;[oldS, s] = [s, oldS - q * s]
	}
	if (oldR !== 1n) throw new Error('modInv: not invertible')
	return mod(oldS, m)
}

function modPow(base: bigint, exp: bigint, m: bigint): bigint {
	let result = 1n
	base = mod(base, m)
	while (exp > 0n) {
		if (exp & 1n) result = mod(result * base, m)
		base = mod(base * base, m)
		exp >>= 1n
	}
	return result
}

function pointAdd(a: Point, b: Point): Point {
	if (a === null) return b
	if (b === null) return a
	if (a.x === b.x && mod(a.y + b.y, P) === 0n) return null
	let lam: bigint
	if (a.x === b.x && a.y === b.y) {
		lam = mod(3n * a.x * a.x * modInv(2n * a.y, P), P)
	} else {
		lam = mod((b.y - a.y) * modInv(mod(b.x - a.x, P), P), P)
	}
	const x = mod(lam * lam - a.x - b.x, P)
	const y = mod(lam * (a.x - x) - a.y, P)
	return { x, y }
}

function pointMul(k: bigint, point: Point): Point {
	let result: Point = null
	let addend = point
	k = mod(k, N)
	while (k > 0n) {
		if (k & 1n) result = pointAdd(result, addend)
		addend = pointAdd(addend, addend)
		k >>= 1n
	}
	return result
}

const G: Point = { x: GX, y: GY }

function bytesToBigInt(buf: Buffer): bigint {
	return BigInt('0x' + (Buffer.from(buf).toString('hex') || '0'))
}

function bigIntTo32(n: bigint): Buffer {
	return Buffer.from(n.toString(16).padStart(64, '0'), 'hex')
}

function liftX(x: bigint): { x: bigint; y: bigint } {
	if (x <= 0n || x >= P) throw new Error('liftX: x out of range')
	const c = mod(x * x * x + 7n, P)
	const y = modPow(c, (P + 1n) / 4n, P)
	if (mod(y * y, P) !== c) throw new Error('liftX: no square root (invalid pubkey)')
	return { x, y: y % 2n === 0n ? y : P - y }
}

function taggedHash(tag: string, ...msgs: Buffer[]): Buffer {
	const tagHash = sha256(Buffer.from(tag, 'utf8'))
	return sha256(Buffer.concat([tagHash, tagHash, ...msgs]))
}

/** Derive the x-only public key (hex) from a 32-byte secret key (hex). */
export function getPublicKey(seckeyHex: string): string {
	const d = BigInt('0x' + seckeyHex)
	if (d <= 0n || d >= N) throw new Error('invalid secret key')
	const pt = pointMul(d, G)
	if (pt === null) throw new Error('invalid secret key')
	return bigIntTo32(pt.x).toString('hex')
}

/** Generate a fresh keypair. Returns { seckey, pubkey } hex strings. */
export function generateKeypair(): { seckey: string; pubkey: string } {
	for (;;) {
		const sec = randomBytes(32)
		const d = bytesToBigInt(sec)
		if (d > 0n && d < N) {
			return { seckey: sec.toString('hex'), pubkey: getPublicKey(sec.toString('hex')) }
		}
	}
}

/** BIP-340 Schnorr signature over a 32-byte message. Returns 64-byte sig hex. */
export function schnorrSign(
	msg32: Buffer | string,
	seckeyHex: string,
	auxRand: Buffer = randomBytes(32),
): string {
	const msg = Buffer.isBuffer(msg32) ? msg32 : Buffer.from(msg32, 'hex')
	if (msg.length !== 32) throw new Error('schnorrSign: message must be 32 bytes')
	let d = BigInt('0x' + seckeyHex)
	if (d <= 0n || d >= N) throw new Error('invalid secret key')
	const pt = pointMul(d, G)
	if (pt === null) throw new Error('invalid secret key')
	if (pt.y % 2n !== 0n) d = N - d
	const pubBytes = bigIntTo32(pt.x)
	const t = bigIntTo32(d ^ bytesToBigInt(taggedHash('BIP0340/aux', auxRand)))
	const rand = taggedHash('BIP0340/nonce', t, pubBytes, msg)
	let k = mod(bytesToBigInt(rand), N)
	if (k === 0n) throw new Error('schnorrSign: zero nonce')
	const R = pointMul(k, G)
	if (R === null) throw new Error('schnorrSign: zero nonce')
	if (R.y % 2n !== 0n) k = N - k
	const e = mod(bytesToBigInt(taggedHash('BIP0340/challenge', bigIntTo32(R.x), pubBytes, msg)), N)
	const sig = Buffer.concat([bigIntTo32(R.x), bigIntTo32(mod(k + e * d, N))])
	if (!schnorrVerify(msg, pubBytes.toString('hex'), sig.toString('hex'))) {
		throw new Error('schnorrSign: self-verification failed')
	}
	return sig.toString('hex')
}

/** BIP-340 Schnorr verification. */
export function schnorrVerify(msg32: Buffer | string, pubkeyHex: string, sigHex: string): boolean {
	try {
		const msg = Buffer.isBuffer(msg32) ? msg32 : Buffer.from(msg32, 'hex')
		const pt = liftX(BigInt('0x' + pubkeyHex))
		const r = BigInt('0x' + sigHex.slice(0, 64))
		const s = BigInt('0x' + sigHex.slice(64, 128))
		if (r >= P || s >= N) return false
		const e = mod(
			bytesToBigInt(taggedHash('BIP0340/challenge', bigIntTo32(r), bigIntTo32(pt.x), msg)),
			N,
		)
		const R = pointAdd(pointMul(s, G), pointMul(N - e, { x: pt.x, y: pt.y }))
		return R !== null && R.y % 2n === 0n && R.x === r
	} catch {
		return false
	}
}

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

function bech32Polymod(values: number[]): number {
	const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
	let chk = 1
	for (const v of values) {
		const b = chk >> 25
		chk = ((chk & 0x1ffffff) << 5) ^ v
		for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]
	}
	return chk
}

function bech32HrpExpand(hrp: string): number[] {
	const out: number[] = []
	for (const c of hrp) out.push(c.charCodeAt(0) >> 5)
	out.push(0)
	for (const c of hrp) out.push(c.charCodeAt(0) & 31)
	return out
}

function convertBits(data: number[], from: number, to: number, pad: boolean): number[] {
	let acc = 0
	let bits = 0
	const out: number[] = []
	const maxv = (1 << to) - 1
	for (const value of data) {
		if (value < 0 || value >> from) throw new Error('bech32: invalid data')
		acc = (acc << from) | value
		bits += from
		while (bits >= to) {
			bits -= to
			out.push((acc >> bits) & maxv)
		}
	}
	if (pad) {
		if (bits > 0) out.push((acc << (to - bits)) & maxv)
	} else if (bits >= from || (acc << (to - bits)) & maxv) {
		throw new Error('bech32: invalid padding')
	}
	return out
}

/** Decode a bech32 string; returns { hrp, bytes }. */
export function bech32Decode(str: string): { hrp: string; bytes: Buffer } {
	const lowered = str.toLowerCase()
	const pos = lowered.lastIndexOf('1')
	if (pos < 1 || pos + 7 > lowered.length) throw new Error('bech32: malformed')
	const hrp = lowered.slice(0, pos)
	const data: number[] = []
	for (const c of lowered.slice(pos + 1)) {
		const d = CHARSET.indexOf(c)
		if (d === -1) throw new Error('bech32: invalid character')
		data.push(d)
	}
	if (bech32Polymod([...bech32HrpExpand(hrp), ...data]) !== 1) {
		throw new Error('bech32: bad checksum')
	}
	return { hrp, bytes: Buffer.from(convertBits(data.slice(0, -6), 5, 8, false)) }
}

/** Encode bytes as bech32 with the given hrp (e.g. npub). */
export function bech32Encode(hrp: string, bytes: Buffer): string {
	const data = convertBits([...bytes], 8, 5, true)
	const values = [...bech32HrpExpand(hrp), ...data]
	const polymod = bech32Polymod([...values, 0, 0, 0, 0, 0, 0]) ^ 1
	let checksum = ''
	for (let i = 0; i < 6; i++) checksum += CHARSET[(polymod >> (5 * (5 - i))) & 31]
	return hrp + '1' + data.map((d) => CHARSET[d]).join('') + checksum
}

/** Normalize a private key (hex or nsec bech32) to 64-char hex. */
export function normalizeSecretKey(key: string): string {
	const trimmed = key.trim()
	if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return trimmed.toLowerCase()
	if (trimmed.startsWith('nsec1')) {
		const { hrp, bytes } = bech32Decode(trimmed)
		if (hrp !== 'nsec' || bytes.length !== 32) throw new Error('invalid nsec')
		return bytes.toString('hex')
	}
	throw new Error('BUZZ_PRIVATE_KEY must be 64-char hex or nsec1...')
}

/** Normalize a public key (hex or npub) to 64-char hex. */
export function normalizePublicKey(key: string): string {
	const trimmed = key.trim()
	if (/^[0-9a-fA-F]{64}$/.test(trimmed)) return trimmed.toLowerCase()
	if (trimmed.startsWith('npub1')) {
		const { hrp, bytes } = bech32Decode(trimmed)
		if (hrp !== 'npub' || bytes.length !== 32) throw new Error('invalid npub')
		return bytes.toString('hex')
	}
	throw new Error('public key must be 64-char hex or npub1...')
}

export type AuthTag = [string, string, string, string]

/**
 * Mint a NIP-OA owner attestation (`auth` tag) authorizing agentPubkey,
 * signed by the owner's secret key.
 * Preimage: "nostr:agent-auth:" || agent_pubkey || ":" || conditions
 */
export function mintOwnerAttestation(
	ownerSeckeyHex: string,
	agentPubkeyHex: string,
	conditions = '',
): AuthTag {
	const preimage = Buffer.from(`nostr:agent-auth:${agentPubkeyHex}:${conditions}`, 'utf8')
	const msg = sha256(preimage)
	const sig = schnorrSign(msg, ownerSeckeyHex)
	const ownerPubkey = getPublicKey(ownerSeckeyHex)
	if (ownerPubkey === agentPubkeyHex) throw new Error('NIP-OA forbids self-attestation')
	return ['auth', ownerPubkey, conditions, sig]
}

/** Verify a NIP-OA auth tag against an agent pubkey. */
export function verifyOwnerAttestation(tag: unknown, agentPubkeyHex: string): boolean {
	if (!Array.isArray(tag) || tag.length !== 4 || tag[0] !== 'auth') return false
	const [, ownerPubkey, conditions, sig] = tag as AuthTag
	if (ownerPubkey === agentPubkeyHex) return false
	const preimage = Buffer.from(`nostr:agent-auth:${agentPubkeyHex}:${conditions}`, 'utf8')
	return schnorrVerify(sha256(preimage), ownerPubkey, sig)
}

// ---------------------------------------------------------------------------
// Config and state
// ---------------------------------------------------------------------------

export const STATE_DIR =
	process.env.AMP_BUZZ_STATE_DIR || path.join(os.homedir(), '.config', 'amp-buzz')

export interface BuzzConfig {
	relayUrl: string
	userSeckey: string
	userPubkey: string
	buzzBin: string
	channelPrefix: string
}

export interface AgentIdentity {
	seckey: string
	pubkey: string
	authTag: AuthTag
}

export interface SessionState {
	channel_id: string
	channel_name: string
	created_at: number
	last_seen: number
	seen_event_ids: string[]
}

export function readJson<T>(file: string, fallback: T | null = null): T | null {
	try {
		return JSON.parse(fs.readFileSync(file, 'utf8')) as T
	} catch {
		return fallback
	}
}

export function writeJson(file: string, data: unknown): void {
	fs.mkdirSync(path.dirname(file), { recursive: true })
	const tmp = file + '.tmp'
	fs.writeFileSync(tmp, JSON.stringify(data, null, 2), { mode: 0o600 })
	fs.renameSync(tmp, file)
}

export function logError(context: string, err: unknown): void {
	try {
		fs.mkdirSync(STATE_DIR, { recursive: true })
		const detail = err instanceof Error && err.stack ? err.stack : String(err)
		fs.appendFileSync(
			path.join(STATE_DIR, 'error.log'),
			`${new Date().toISOString()} [${context}] ${detail}\n`,
		)
	} catch {
		// last resort: swallow
	}
}

/**
 * Resolve plugin configuration. Env vars win over the config file
 * (~/.config/amp-buzz/config.json: { "relay_url", "private_key" }).
 * Returns null when no relay is configured — the plugin is inert then.
 */
export function loadConfig(): BuzzConfig | null {
	// When this process is itself a managed Buzz agent (e.g. an Amp instance
	// driven by buzz-acp), its identity is an agent key and its turns already
	// live on the relay — mirroring them again would spam channels.
	if (process.env.BUZZ_MANAGED_AGENT || process.env.BUZZ_AUTH_TAG) return null
	const file =
		readJson<Record<string, string>>(path.join(STATE_DIR, 'config.json'), {}) ?? {}
	const relayUrl = process.env.BUZZ_RELAY_URL || file.relay_url
	const rawKey = process.env.BUZZ_PRIVATE_KEY || file.private_key
	if (!relayUrl || !rawKey) return null
	const userSeckey = normalizeSecretKey(rawKey)
	return {
		relayUrl,
		userSeckey,
		userPubkey: getPublicKey(userSeckey),
		buzzBin: process.env.AMP_BUZZ_BIN || file.buzz_bin || 'buzz',
		channelPrefix: process.env.AMP_BUZZ_CHANNEL_PREFIX || file.channel_prefix || 'amp',
	}
}

// ---------------------------------------------------------------------------
// buzz CLI invocation
// ---------------------------------------------------------------------------

interface Identity {
	seckey: string
	authTag?: AuthTag
}

function buzzEnv(config: BuzzConfig, identity: Identity): NodeJS.ProcessEnv {
	const env: NodeJS.ProcessEnv = {
		...process.env,
		BUZZ_RELAY_URL: config.relayUrl,
		BUZZ_PRIVATE_KEY: identity.seckey,
	}
	if (identity.authTag) env.BUZZ_AUTH_TAG = JSON.stringify(identity.authTag)
	else delete env.BUZZ_AUTH_TAG
	return env
}

/**
 * Run the buzz CLI as a given identity and parse its JSON output.
 * identity: { seckey, authTag? } — authTag is the NIP-OA tag JSON for agent keys.
 */
export function buzz(
	config: BuzzConfig,
	identity: Identity,
	args: string[],
	{ allowFailure = false, input }: { allowFailure?: boolean; input?: string } = {},
): any {
	try {
		const out = execFileSync(config.buzzBin, args, {
			env: buzzEnv(config, identity),
			encoding: 'utf8',
			timeout: 20_000,
			maxBuffer: 16 * 1024 * 1024,
			input,
			stdio: ['pipe', 'pipe', 'pipe'],
		})
		const trimmed = out.trim()
		if (!trimmed) return null
		try {
			return JSON.parse(trimmed)
		} catch {
			return trimmed
		}
	} catch (err: any) {
		if (allowFailure) return { error: true, message: String(err.stderr || err.message) }
		const detail = err.stderr ? `: ${String(err.stderr).trim()}` : ''
		throw new Error(`buzz ${args[0]} ${args[1] || ''} failed${detail}`)
	}
}

/** Send a message with content passed via stdin (preserves newlines). */
export function buzzSend(
	config: BuzzConfig,
	identity: Identity,
	channelId: string,
	content: string,
	{ mentions = [] as string[] } = {},
): any {
	const args = ['messages', 'send', '--channel', channelId, '--content', '-']
	for (const m of mentions) args.push('--mention', m)
	return buzz(config, identity, args, { input: content })
}

// ---------------------------------------------------------------------------
// Agent identity
// ---------------------------------------------------------------------------

const AGENT_FILE = () => path.join(STATE_DIR, 'agent.json')
const AGENT_NAME = 'Amp'

/**
 * Ensure the plugin's agent identity exists: a keypair distinct from the
 * user's, carrying a NIP-OA owner attestation minted with the user's key.
 * The agent identity is per-machine and reused across threads.
 *
 * Externally provisioned identities (e.g. an agent created in Buzz Desktop)
 * are supported by placing { seckey, pubkey, auth_tag } in agent.json —
 * an existing valid file is never overwritten.
 */
export function ensureAgentIdentity(config: BuzzConfig): AgentIdentity {
	const existing = readJson<{ seckey: string; pubkey: string; auth_tag: AuthTag }>(AGENT_FILE())
	if (
		existing &&
		existing.seckey &&
		existing.pubkey &&
		Array.isArray(existing.auth_tag) &&
		verifyOwnerAttestation(existing.auth_tag, existing.pubkey)
	) {
		return { seckey: existing.seckey, pubkey: existing.pubkey, authTag: existing.auth_tag }
	}

	const kp = generateKeypair()
	const authTag = mintOwnerAttestation(config.userSeckey, kp.pubkey, '')
	writeJson(AGENT_FILE(), {
		seckey: kp.seckey,
		pubkey: kp.pubkey,
		auth_tag: authTag,
		owner_pubkey: config.userPubkey,
		created_at: Math.floor(Date.now() / 1000),
	})

	const agent: AgentIdentity = { seckey: kp.seckey, pubkey: kp.pubkey, authTag }
	// Best-effort profile so other clients render a name for the agent.
	buzz(
		config,
		agent,
		[
			'users',
			'set-profile',
			'--name',
			`${AGENT_NAME} (${os.hostname().replace(/\.local$/, '')})`,
			'--about',
			'Amp thread agent — via the amp-buzz plugin',
		],
		{ allowFailure: true },
	)
	return agent
}

// ---------------------------------------------------------------------------
// Session (per-thread) state and channel operations
// ---------------------------------------------------------------------------

const MAX_MIRROR_CHARS = 8000

function sessionFile(threadId: string): string {
	return path.join(STATE_DIR, 'sessions', `${threadId}.json`)
}

export function loadSession(threadId: string): SessionState | null {
	return readJson<SessionState>(sessionFile(threadId))
}

export function saveSession(threadId: string, state: SessionState): void {
	writeJson(sessionFile(threadId), state)
}

export function slugify(text: string, maxLen = 40): string {
	const slug = text
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '')
		.slice(0, maxLen)
		.replace(/-+$/, '')
	return slug || `thread-${Math.floor(Date.now() / 1000)}`
}

export function truncate(text: string, max = MAX_MIRROR_CHARS): string {
	if (text.length <= max) return text
	return text.slice(0, max) + `\n… [truncated, ${text.length - max} more chars]`
}

/**
 * Create the session channel following the required bootstrap order:
 * create channel → add agent as member with role bot →
 * first prompt (sent by the caller) carries the agent's p-tag mention.
 */
export function createSessionChannel(
	config: BuzzConfig,
	agent: AgentIdentity,
	threadId: string,
	firstPrompt: string,
): { id: string; name: string } {
	const baseName = `${config.channelPrefix}--${slugify(firstPrompt)}`
	let channel: { id: string; name: string } | null = null
	let name = baseName
	for (let attempt = 0; attempt < 3 && !channel; attempt++) {
		const res = buzz(
			config,
			{ seckey: config.userSeckey },
			[
				'channels',
				'create',
				'--name',
				name,
				'--type',
				'stream',
				'--visibility',
				'private',
				'--description',
				`Amp thread ${threadId}`,
			],
			{ allowFailure: true },
		)
		const channelId = res && (res.channel_id || (res.channel && res.channel.channel_id))
		if (channelId) {
			channel = { id: channelId, name }
		} else {
			name = `${baseName}-${Math.random().toString(16).slice(2, 6)}`
		}
	}
	if (!channel) throw new Error('failed to create session channel')

	buzz(config, { seckey: config.userSeckey }, [
		'channels',
		'add-member',
		'--channel',
		channel.id,
		'--pubkey',
		agent.pubkey,
		'--role',
		'bot',
	])
	return channel
}

/** Publish a user prompt to the channel, signed by the user's key. */
export function mirrorPrompt(
	config: BuzzConfig,
	agent: AgentIdentity,
	state: SessionState,
	prompt: string,
	{ mentionAgent = false } = {},
): any {
	return buzzSend(config, { seckey: config.userSeckey }, state.channel_id, truncate(prompt), {
		mentions: mentionAgent ? [agent.pubkey] : [],
	})
}

/** Publish the agent's reply, signed by the agent key (never the user's). */
export function mirrorReply(
	config: BuzzConfig,
	agent: AgentIdentity,
	state: SessionState,
	reply: string,
): any {
	return buzzSend(
		config,
		{ seckey: agent.seckey, authTag: agent.authTag },
		state.channel_id,
		truncate(reply),
	)
}

export interface RemoteMessage {
	id: string
	pubkey: string
	author: string
	content: string
	created_at: number
	mentions_agent: boolean
}

/**
 * Fetch channel messages that arrived from remote participants (anyone other
 * than the local user and agent) since the last check. Advances the cursor.
 */
export function fetchRemoteMessages(
	config: BuzzConfig,
	agent: AgentIdentity,
	state: SessionState,
): RemoteMessage[] {
	const args = ['messages', 'get', '--channel', state.channel_id, '--limit', '100']
	if (state.last_seen) args.push('--since', String(state.last_seen))
	const res = buzz(config, { seckey: config.userSeckey }, args, { allowFailure: true })
	if (!res || res.error) return []
	const messages: any[] = Array.isArray(res) ? res : res.messages || res.events || []
	const seen = new Set(state.seen_event_ids || [])
	const locals = new Set([config.userPubkey, agent.pubkey])
	const remote: RemoteMessage[] = []
	let maxTs = state.last_seen || 0
	for (const m of messages) {
		const id = m.event_id || m.id
		const ts = m.created_at || 0
		if (ts > maxTs) maxTs = ts
		if (id && seen.has(id)) continue
		if (id) seen.add(id)
		if (locals.has(m.pubkey)) continue
		if (typeof m.content !== 'string' || !m.content.trim()) continue
		remote.push({
			id,
			pubkey: m.pubkey,
			author: m.author_name || m.author || (m.pubkey ? m.pubkey.slice(0, 8) : 'unknown'),
			content: m.content,
			created_at: ts,
			mentions_agent: JSON.stringify(m.tags || []).includes(agent.pubkey),
		})
	}
	state.last_seen = maxTs
	state.seen_event_ids = [...seen].slice(-300)
	return remote
}

export function formatRemoteContext(state: SessionState, remote: RemoteMessage[]): string {
	const lines = remote.map((m) => {
		const flag = m.mentions_agent ? ' [mentions you]' : ''
		return `- ${m.author}${flag}: ${truncate(m.content, 2000)}`
	})
	return [
		`New messages from remote participants on Buzz channel #${state.channel_name} (this thread is mirrored there):`,
		...lines,
		'These are conversation context from collaborators watching this thread. Take them into account; address them directly only when relevant to the current prompt.',
	].join('\n')
}

/** Collect the assistant's text output from an agent.end message list. */
export function extractAssistantText(messages: ThreadMessage[]): string {
	const parts: string[] = []
	for (const msg of messages) {
		if (msg.role !== 'assistant') continue
		for (const block of msg.content) {
			if (block.type === 'text' && block.text.trim()) parts.push(block.text)
		}
	}
	return parts.join('\n\n').trim()
}

// ---------------------------------------------------------------------------
// Plugin entrypoint
// ---------------------------------------------------------------------------

export default function (amp: PluginAPI) {
	const config = loadConfig()
	if (!config) {
		amp.logger.log(
			'amp-buzz: no relay configured (set BUZZ_RELAY_URL and BUZZ_PRIVATE_KEY); plugin is inert',
		)
		return
	}
	amp.logger.log(`amp-buzz: mirroring threads to ${config.relayUrl}`)

	amp.on('agent.start', (event: AgentStartEvent) => {
		try {
			const prompt = (event.message || '').trim()
			if (!prompt) return {}
			const agent = ensureAgentIdentity(config)
			let state = loadSession(event.thread.id)
			let firstPrompt = false

			if (!state || !state.channel_id) {
				const channel = createSessionChannel(config, agent, event.thread.id, prompt)
				state = {
					channel_id: channel.id,
					channel_name: channel.name,
					created_at: Math.floor(Date.now() / 1000),
					last_seen: Math.floor(Date.now() / 1000) - 5,
					seen_event_ids: [],
				}
				firstPrompt = true
			}

			mirrorPrompt(config, agent, state, prompt, { mentionAgent: firstPrompt })
			const remote = fetchRemoteMessages(config, agent, state)
			saveSession(event.thread.id, state)

			const contextParts: string[] = []
			if (firstPrompt) {
				contextParts.push(
					`This thread is now mirrored to Buzz channel #${state.channel_name} on ${config.relayUrl}. Your replies are published there under the thread's agent identity; remote collaborators may join and post.`,
				)
			}
			if (remote.length > 0) contextParts.push(formatRemoteContext(state, remote))
			if (contextParts.length > 0) {
				return { message: { content: contextParts.join('\n\n'), display: false } }
			}
		} catch (err) {
			logError('agent.start', err)
		}
		return {}
	})

	amp.on('agent.end', (event: AgentEndEvent) => {
		try {
			const state = loadSession(event.thread.id)
			if (!state || !state.channel_id) return
			const reply = extractAssistantText(event.messages)
			if (!reply) return
			const agent = ensureAgentIdentity(config)
			mirrorReply(config, agent, state, reply)
		} catch (err) {
			logError('agent.end', err)
		}
	})

	amp.registerCommand(
		'status',
		{ title: 'Status', category: 'Buzz', description: 'Show Buzz mirroring status for this thread' },
		async (ctx) => {
			try {
				const agent = ensureAgentIdentity(config)
				const lines = [
					`Relay: ${config.relayUrl}`,
					`Your pubkey: ${config.userPubkey}`,
					`Agent pubkey: ${agent.pubkey} (${bech32Encode('npub', Buffer.from(agent.pubkey, 'hex'))})`,
				]
				const state = ctx.thread ? loadSession(ctx.thread.id) : null
				lines.push(
					state
						? `This thread → channel #${state.channel_name} (${state.channel_id})`
						: 'This thread is not mirrored yet (the channel is created on your first prompt).',
				)
				await ctx.ui.notify(lines.join('\n'))
			} catch (err) {
				logError('command.status', err)
			}
		},
	)

	amp.registerCommand(
		'invite',
		{
			title: 'Invite',
			category: 'Buzz',
			description: "Add a collaborator (pubkey or npub) to this thread's Buzz channel",
		},
		async (ctx) => {
			try {
				const state = ctx.thread ? loadSession(ctx.thread.id) : null
				if (!state) {
					await ctx.ui.notify('This thread has no Buzz channel yet — send a prompt first.')
					return
				}
				const raw = await ctx.ui.input({
					title: 'Invite to Buzz channel',
					helpText: 'hex pubkey or npub1…',
				})
				if (!raw) return
				const pubkey = normalizePublicKey(raw)
				buzz(config, { seckey: config.userSeckey }, [
					'channels',
					'add-member',
					'--channel',
					state.channel_id,
					'--pubkey',
					pubkey,
					'--role',
					'member',
				])
				await ctx.ui.notify(`Added ${pubkey.slice(0, 8)}… to #${state.channel_name}`)
			} catch (err) {
				logError('command.invite', err)
				await ctx.ui.notify(`Invite failed: ${err instanceof Error ? err.message : err}`)
			}
		},
	)

	amp.registerCommand(
		'chat',
		{
			title: 'Chat',
			category: 'Buzz',
			description: "Post a message to this thread's Buzz channel without prompting the agent",
		},
		async (ctx) => {
			try {
				const state = ctx.thread ? loadSession(ctx.thread.id) : null
				if (!state) {
					await ctx.ui.notify('This thread has no Buzz channel yet — send a prompt first.')
					return
				}
				const content = await ctx.ui.input({
					title: `Chat on #${state.channel_name}`,
					helpText: 'message…',
				})
				if (!content) return
				buzzSend(config, { seckey: config.userSeckey }, state.channel_id, content)
				await ctx.ui.notify(`Posted to #${state.channel_name}`)
			} catch (err) {
				logError('command.chat', err)
				await ctx.ui.notify(`Chat failed: ${err instanceof Error ? err.message : err}`)
			}
		},
	)

	amp.registerCommand(
		'catchup',
		{
			title: 'Catch up',
			category: 'Buzz',
			description: 'Show messages remote collaborators posted since the last turn',
		},
		async (ctx) => {
			try {
				const state = ctx.thread ? loadSession(ctx.thread.id) : null
				if (!state) {
					await ctx.ui.notify('This thread has no Buzz channel yet — send a prompt first.')
					return
				}
				const agent = ensureAgentIdentity(config)
				// Peek without advancing the cursor so the messages still reach
				// the agent as context on the next turn.
				const peek: SessionState = { ...state, seen_event_ids: [...state.seen_event_ids] }
				const remote = fetchRemoteMessages(config, agent, peek)
				await ctx.ui.notify(
					remote.length === 0
						? `No new remote messages on #${state.channel_name}`
						: remote.map((m) => `${m.author}: ${truncate(m.content, 500)}`).join('\n'),
				)
			} catch (err) {
				logError('command.catchup', err)
			}
		},
	)
}
