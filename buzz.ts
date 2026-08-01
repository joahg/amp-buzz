// @amp-agent-mode {"key":"buzz-chat","label":"buzz chat"}
/**
 * amp-buzz — turn Amp into a buzz:// client.
 *
 * Every Amp thread is mirrored to a private channel on your Buzz relay,
 * created and owned by a dedicated per-session agent key carrying a NIP-OA
 * owner attestation. Your user account is never added to these channels
 * (they stay out of your Buzz sidebar): prompts and replies both publish
 * under the agent key, prompts prefixed with your display name. Channels
 * you join explicitly (/join) keep publishing your prompts under your key.
 * Channel messages posted from Buzz (by collaborators) appear in the Amp
 * chat transcript (never auto-dispatching a turn).
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
	ThreadID,
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
	/** Extra pubkeys (beyond the owner and channel owners/admins) allowed to trigger turns by mentioning the agent. */
	triggerPubkeys: string[]
}

export interface AgentIdentity {
	seckey: string
	pubkey: string
	authTag: AuthTag
	name: string
}

export interface SessionAgentRecord {
	seckey: string
	pubkey: string
	auth_tag: AuthTag
	name: string
}

export interface SessionState {
	channel_id: string
	channel_name: string
	created_at: number
	last_seen: number
	seen_event_ids: string[]
	agent?: SessionAgentRecord
	/**
	 * Whether the user's account is a member of the channel. False for
	 * channels this plugin creates (agent-owned; the user is never added,
	 * so they stay out of the user's sidebar) — there the user's prompts
	 * publish under the agent key with a `<name>: ` prefix, because the
	 * relay rejects posts to private channels from non-members.
	 * Absent (legacy sessions) and /join-ed channels mean true.
	 */
	user_is_member?: boolean
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
	const rawTriggers = process.env.AMP_BUZZ_TRIGGER_PUBKEYS
		? process.env.AMP_BUZZ_TRIGGER_PUBKEYS.split(',')
		: Array.isArray((file as Record<string, unknown>).trigger_pubkeys)
			? ((file as Record<string, unknown>).trigger_pubkeys as string[])
			: []
	const triggerPubkeys: string[] = []
	for (const raw of rawTriggers) {
		try {
			triggerPubkeys.push(normalizePublicKey(String(raw).trim()))
		} catch {
			// skip invalid entries
		}
	}
	return {
		relayUrl,
		userSeckey,
		userPubkey: getPublicKey(userSeckey),
		buzzBin: process.env.AMP_BUZZ_BIN || file.buzz_bin || 'buzz',
		channelPrefix: process.env.AMP_BUZZ_CHANNEL_PREFIX || file.channel_prefix || 'amp',
		triggerPubkeys,
	}
}

// ---------------------------------------------------------------------------
// buzz CLI invocation
// ---------------------------------------------------------------------------

interface Identity {
	seckey: string
	authTag?: AuthTag
}

/** CLI identity for an agent key (seckey + NIP-OA attestation). */
function agentIdentity(agent: AgentIdentity): Identity {
	return { seckey: agent.seckey, authTag: agent.authTag }
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

function sendArgs(channelId: string, mentions: string[]): string[] {
	const args = ['messages', 'send', '--channel', channelId, '--content', '-']
	for (const m of mentions) args.push('--mention', m)
	return args
}

/**
 * Send a message with content passed via stdin (preserves newlines).
 *
 * The buzz CLI refuses to send content whose `@name` text does not resolve to
 * a channel member. When that happens, resolve what we can (channel members
 * by profile name, then exact-name relay users — who get added to the channel
 * and notified) and neutralize the rest so the send never hard-fails on
 * incidental @text.
 */
export function buzzSend(
	config: BuzzConfig,
	identity: Identity,
	channelId: string,
	content: string,
	{ mentions = [] as string[] } = {},
): any {
	const first = buzz(config, identity, sendArgs(channelId, mentions), {
		input: content,
		allowFailure: true,
	})
	if (!first || !first.error) return first
	if (!/mention/i.test(String(first.message))) throw new Error(String(first.message))

	const { content: resolvedContent, mentions: extra } = resolveMentions(
		config,
		channelId,
		content,
		identity,
	)
	const second = buzz(
		config,
		identity,
		sendArgs(channelId, [...new Set([...mentions, ...extra])]),
		{ input: resolvedContent, allowFailure: true },
	)
	if (!second || !second.error) return second

	// Last resort: neutralize every @ so the CLI cannot parse any mention.
	const neutral = content.replace(/@(?=\S)/g, '@\u200b')
	return buzz(config, identity, sendArgs(channelId, mentions), { input: neutral })
}

// ---------------------------------------------------------------------------
// Mentions
// ---------------------------------------------------------------------------

const MENTION_TOKEN_RE = /(^|[\s(])@([A-Za-z0-9._-]{1,64})/g

/** Extract candidate @name tokens from message text. */
export function extractMentionTokens(content: string): string[] {
	const tokens = new Set<string>()
	for (const m of content.matchAll(MENTION_TOKEN_RE)) tokens.add(m[2])
	return [...tokens]
}

function escapeRegex(s: string): string {
	return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
}

/**
 * Neutralize the given @tokens with a zero-width space so the buzz CLI stops
 * treating them as mentions. Renders identically for readers.
 */
export function sanitizeMentions(content: string, tokens: string[]): string {
	let out = content
	for (const t of tokens) {
		const re = new RegExp(`(^|[\\s(])@(${escapeRegex(t)})(?![A-Za-z0-9._-])`, 'g')
		out = out.replace(re, '$1@\u200b$2')
	}
	return out
}

export interface ChannelInfo {
	channel_id: string
	name: string
	description?: string
}

/** List relay channels visible to the user, filtered by a substring query. */
export function listChannels(config: BuzzConfig, query = ''): ChannelInfo[] {
	const res = buzz(config, { seckey: config.userSeckey }, ['channels', 'list', '--limit', '500'], {
		allowFailure: true,
	})
	const channels: ChannelInfo[] = (Array.isArray(res) ? res : []).filter(
		(c: any) => c && typeof c.channel_id === 'string' && typeof c.name === 'string',
	)
	const q = query.trim().toLowerCase()
	const filtered = q
		? channels.filter(
				(c) =>
					c.name.toLowerCase().includes(q) || (c.description || '').toLowerCase().includes(q),
			)
		: channels
	return filtered.sort((a, b) => a.name.localeCompare(b.name))
}

export interface HistoryMessage {
	id: string
	pubkey: string
	content: string
	created_at: number
}

const HISTORY_PAGE = 200
export const HISTORY_MAX = 500

/**
 * Fetch a channel's message history (up to `max` most recent messages),
 * paginating backwards with --before. Returned oldest-first.
 */
export function fetchChannelHistory(
	config: BuzzConfig,
	channelId: string,
	max = HISTORY_MAX,
): HistoryMessage[] {
	const byId = new Map<string, HistoryMessage>()
	let before: number | undefined
	for (let page = 0; page < Math.ceil(max / HISTORY_PAGE) + 1; page++) {
		const args = ['messages', 'get', '--channel', channelId, '--limit', String(HISTORY_PAGE)]
		if (before !== undefined) args.push('--before', String(before))
		const res = buzz(config, { seckey: config.userSeckey }, args, { allowFailure: true })
		const messages: any[] = Array.isArray(res) ? res : []
		if (messages.length === 0) break
		let oldest = Infinity
		for (const m of messages) {
			const id = m.event_id || m.id
			const ts = m.created_at || 0
			if (ts > 0 && ts < oldest) oldest = ts
			if (!id || typeof m.content !== 'string' || !m.content.trim()) continue
			byId.set(id, { id, pubkey: m.pubkey, content: m.content, created_at: ts })
		}
		if (messages.length < HISTORY_PAGE || !Number.isFinite(oldest) || byId.size >= max) break
		before = oldest
	}
	return [...byId.values()].sort((a, b) => a.created_at - b.created_at).slice(-max)
}

/**
 * Batch channel history into transcript-ready blocks. Each block carries the
 * INCOMING_MARK prefix so agent.start cancels its turn, and stays under
 * `maxBlock` chars so a long history imports as a handful of appends instead
 * of one per message.
 */
export function formatHistoryBlocks(
	messages: Array<{ author: string; content: string }>,
	maxBlock = 8000,
): string[] {
	const blocks: string[] = []
	let cur: string[] = []
	let curLen = 0
	for (const m of messages) {
		const line = `${m.author}: ${truncate(m.content, 1500)}`
		if (cur.length > 0 && curLen + line.length + 2 > maxBlock) {
			blocks.push(INCOMING_MARK + cur.join('\n\n'))
			cur = []
			curLen = 0
		}
		cur.push(line)
		curLen += line.length + 2
	}
	if (cur.length > 0) blocks.push(INCOMING_MARK + cur.join('\n\n'))
	return blocks
}

export function channelMembers(
	config: BuzzConfig,
	channelId: string,
	identity: Identity = { seckey: config.userSeckey },
): Array<{ pubkey: string; role?: string }> {
	const res = buzz(config, identity, ['channels', 'members', '--channel', channelId], {
		allowFailure: true,
	})
	return Array.isArray(res) ? res : []
}

/** Map pubkey → display name for the given pubkeys. */
export function userProfiles(config: BuzzConfig, pubkeys: string[]): Map<string, string> {
	const names = new Map<string, string>()
	if (pubkeys.length === 0) return names
	const args = ['users', 'get']
	for (const p of pubkeys) args.push('--pubkey', p)
	const res = buzz(config, { seckey: config.userSeckey }, args, { allowFailure: true })
	for (const u of Array.isArray(res) ? res : []) {
		if (u.pubkey && u.display_name) names.set(u.pubkey, u.display_name)
	}
	return names
}

/** Case-insensitive substring search of relay users by display name. */
export function searchUsers(
	config: BuzzConfig,
	name: string,
): Array<{ pubkey: string; display_name: string }> {
	const res = buzz(config, { seckey: config.userSeckey }, ['users', 'get', '--name', name], {
		allowFailure: true,
	})
	const seen = new Set<string>()
	const out: Array<{ pubkey: string; display_name: string }> = []
	for (const u of Array.isArray(res) ? res : []) {
		if (!u.pubkey || !u.display_name || seen.has(u.pubkey)) continue
		seen.add(u.pubkey)
		out.push({ pubkey: u.pubkey, display_name: u.display_name })
	}
	return out
}

/**
 * Resolve @tokens in outgoing content: channel members match by profile name;
 * otherwise a unique exact-name relay user is added to the channel (the
 * author explicitly tagged them into the conversation) and mentioned.
 * Unresolvable tokens are neutralized so the send cannot fail on them.
 */
export function resolveMentions(
	config: BuzzConfig,
	channelId: string,
	content: string,
	identity: Identity = { seckey: config.userSeckey },
): { content: string; mentions: string[] } {
	const tokens = extractMentionTokens(content)
	if (tokens.length === 0) return { content, mentions: [] }

	const members = channelMembers(config, channelId, identity)
	const memberPubkeys = new Set(members.map((m) => m.pubkey))
	const profiles = userProfiles(config, [...memberPubkeys])
	const mentions: string[] = []
	const unresolved: string[] = []

	for (const token of tokens) {
		const lower = token.toLowerCase()
		const member = [...profiles.entries()].find(([, name]) => name.toLowerCase() === lower)
		if (member) {
			mentions.push(member[0])
			continue
		}
		const matches = searchUsers(config, token).filter(
			(u) => u.display_name.toLowerCase() === lower && !memberPubkeys.has(u.pubkey),
		)
		if (matches.length === 1) {
			buzz(
				config,
				identity,
				[
					'channels',
					'add-member',
					'--channel',
					channelId,
					'--pubkey',
					matches[0].pubkey,
					'--role',
					'member',
				],
				{ allowFailure: true },
			)
			mentions.push(matches[0].pubkey)
		} else {
			unresolved.push(token)
		}
	}
	return { content: sanitizeMentions(content, unresolved), mentions }
}

// ---------------------------------------------------------------------------
// Agent identity
// ---------------------------------------------------------------------------

const LEGACY_AGENT_FILE = () => path.join(STATE_DIR, 'agent.json')
const AGENT_NAME = 'Amp'

function hostLabel(): string {
	return os.hostname().replace(/\.local$/, '')
}

/**
 * Display name for one session's agent identity: host plus a short thread
 * suffix, so every Amp session shows up on Buzz as a distinct agent.
 */
export function agentDisplayName(threadId: string): string {
	const suffix = threadId
		.replace(/^T-/, '')
		.replace(/[^a-zA-Z0-9]/g, '')
		.slice(0, 8)
	return suffix ? `${AGENT_NAME} (${hostLabel()}-${suffix})` : `${AGENT_NAME} (${hostLabel()})`
}

function toAgentRecord(agent: AgentIdentity): SessionAgentRecord {
	return { seckey: agent.seckey, pubkey: agent.pubkey, auth_tag: agent.authTag, name: agent.name }
}

function fromAgentRecord(rec: SessionAgentRecord, threadId: string): AgentIdentity {
	return {
		seckey: rec.seckey,
		pubkey: rec.pubkey,
		authTag: rec.auth_tag,
		name: rec.name || agentDisplayName(threadId),
	}
}

function validAgentRecord(rec: SessionAgentRecord | undefined): rec is SessionAgentRecord {
	return Boolean(
		rec &&
			rec.seckey &&
			rec.pubkey &&
			Array.isArray(rec.auth_tag) &&
			verifyOwnerAttestation(rec.auth_tag, rec.pubkey),
	)
}

/**
 * Mint a fresh agent identity for one Amp session (thread): its own keypair
 * carrying a NIP-OA owner attestation minted with the user's key, with a
 * relay profile named after the host and thread. The identity lives in the
 * thread's session state and is never shared across sessions.
 */
export function createSessionAgent(config: BuzzConfig, threadId: string): AgentIdentity {
	const kp = generateKeypair()
	const authTag = mintOwnerAttestation(config.userSeckey, kp.pubkey, '')
	const agent: AgentIdentity = {
		seckey: kp.seckey,
		pubkey: kp.pubkey,
		authTag,
		name: agentDisplayName(threadId),
	}
	// Best-effort profile so other clients render a name for the agent.
	buzz(
		config,
		agent,
		[
			'users',
			'set-profile',
			'--name',
			agent.name,
			'--about',
			`Amp session agent (thread ${threadId}) — via the amp-buzz plugin`,
		],
		{ allowFailure: true },
	)
	return agent
}

/**
 * The shared per-machine identity from before per-session identities
 * (~/.config/amp-buzz/agent.json). Sessions created back then keep it —
 * its pubkey is what their channel membership and old mentions reference —
 * but new sessions always mint their own.
 */
export function legacyAgentIdentity(): AgentIdentity | null {
	const existing = readJson<{ seckey: string; pubkey: string; auth_tag: AuthTag }>(
		LEGACY_AGENT_FILE(),
	)
	if (
		existing &&
		existing.seckey &&
		existing.pubkey &&
		Array.isArray(existing.auth_tag) &&
		verifyOwnerAttestation(existing.auth_tag, existing.pubkey)
	) {
		return {
			seckey: existing.seckey,
			pubkey: existing.pubkey,
			authTag: existing.auth_tag,
			name: `${AGENT_NAME} (${hostLabel()})`,
		}
	}
	return null
}

/**
 * Resolve the agent identity for an existing session. Sessions predating
 * per-session identities adopt the legacy shared one; a session with no
 * usable identity at all gets a fresh one, added to its channel as a bot.
 * The resolved identity is persisted into the session state.
 */
export function sessionAgent(
	config: BuzzConfig,
	threadId: string,
	state: SessionState,
): AgentIdentity {
	if (validAgentRecord(state.agent)) return fromAgentRecord(state.agent, threadId)
	const legacy = legacyAgentIdentity()
	const agent = legacy ?? createSessionAgent(config, threadId)
	if (!legacy && state.channel_id) {
		buzz(
			config,
			{ seckey: config.userSeckey },
			[
				'channels',
				'add-member',
				'--channel',
				state.channel_id,
				'--pubkey',
				agent.pubkey,
				'--role',
				'bot',
			],
			{ allowFailure: true },
		)
	}
	state.agent = toAgentRecord(agent)
	saveSession(threadId, state)
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
 * Resolve the channel name prefix: the user's relay profile name (slugified),
 * falling back to the configured prefix when the profile has no name.
 * Shared naming scheme with claude-code-buzz: `<username>--<slug>`.
 */
export function usernameSlug(name: string): string {
	return name
		.toLowerCase()
		.replace(/[^a-z0-9]+/g, '-')
		.replace(/^-+|-+$/g, '')
		.slice(0, 24)
		.replace(/-+$/, '')
}

export function resolveUsername(config: BuzzConfig): string {
	const res = buzz(config, { seckey: config.userSeckey }, ['users', 'get'], {
		allowFailure: true,
	})
	const profile = Array.isArray(res) ? res[0] : res
	const name = profile && typeof profile.display_name === 'string' ? profile.display_name : ''
	return usernameSlug(name) || config.channelPrefix
}

/**
 * Create the session channel, signed by the session's agent identity: the
 * agent becomes the channel's owner (and sole member). The user's account is
 * deliberately never added, so plugin-created channels stay out of the
 * user's Buzz sidebar.
 */
export function createSessionChannel(
	config: BuzzConfig,
	agent: AgentIdentity,
	threadId: string,
	firstPrompt: string,
): { id: string; name: string } {
	const baseName = `${resolveUsername(config)}--${slugify(firstPrompt)}`
	let channel: { id: string; name: string } | null = null
	let name = baseName
	for (let attempt = 0; attempt < 3 && !channel; attempt++) {
		const res = buzz(
			config,
			agentIdentity(agent),
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
	return channel
}

let cachedOwnerName: string | null = null

/** The user's relay display name, for attributing agent-signed prompts. Memoized. */
export function ownerName(config: BuzzConfig): string {
	cachedOwnerName ??= userProfiles(config, [config.userPubkey]).get(config.userPubkey) || null
	return cachedOwnerName || config.userPubkey.slice(0, 8)
}

/**
 * Publish a user prompt to the channel. In channels where the user is a
 * member (/join-ed and legacy sessions) it publishes under the user's key,
 * @-tagging the thread's agent so Buzz clients show who it is directed at.
 * In plugin-created channels the user is not a member (the relay would
 * reject their post), so it publishes under the agent key, prefixed with
 * the user's display name for attribution.
 */
export function mirrorPrompt(
	config: BuzzConfig,
	agent: AgentIdentity,
	state: SessionState,
	prompt: string,
): any {
	if (state.user_is_member === false) {
		const content = `${ownerName(config)}: ${truncate(prompt)}`
		return buzzSend(config, agentIdentity(agent), state.channel_id, content)
	}
	const content = `@${agent.name} ${truncate(prompt)}`
	return buzzSend(config, { seckey: config.userSeckey }, state.channel_id, content, {
		mentions: [agent.pubkey],
	})
}

/** Publish the agent's reply, signed by the agent key (never the user's). */
export function mirrorReply(
	config: BuzzConfig,
	agent: AgentIdentity,
	state: SessionState,
	reply: string,
): any {
	return buzzSend(config, agentIdentity(agent), state.channel_id, truncate(reply))
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
 * Fetch channel messages that arrived from Buzz (anyone other than the thread
 * agent, plus the user's own Buzz-native messages) since the last check.
 * Events this plugin itself published (mirrored prompts/chat) are excluded
 * via `ownEventIds` and the persisted seen set. Advances the cursor.
 * Author pubkeys are resolved to relay profile display names, memoized in
 * `nameCache` ('' marks a known miss so it isn't re-queried).
 */
export function fetchRemoteMessages(
	config: BuzzConfig,
	agent: AgentIdentity,
	state: SessionState,
	{
		ownEventIds,
		nameCache,
	}: { ownEventIds?: Set<string>; nameCache?: Map<string, string> } = {},
): RemoteMessage[] {
	const args = ['messages', 'get', '--channel', state.channel_id, '--limit', '100']
	if (state.last_seen) args.push('--since', String(state.last_seen))
	// Read as the agent: it is a member of every session channel, while the
	// user is not a member of plugin-created ones.
	const res = buzz(config, agentIdentity(agent), args, { allowFailure: true })
	if (!res || res.error) return []
	const messages: any[] = Array.isArray(res) ? res : res.messages || res.events || []
	const seen = new Set(state.seen_event_ids || [])
	const remote: RemoteMessage[] = []
	let maxTs = state.last_seen || 0
	for (const m of messages) {
		const id = m.event_id || m.id
		const ts = m.created_at || 0
		if (ts > maxTs) maxTs = ts
		if (id && (seen.has(id) || ownEventIds?.has(id))) continue
		if (id) seen.add(id)
		if (m.pubkey === agent.pubkey) continue
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

	const cache = nameCache ?? new Map<string, string>()
	const missing = [...new Set(remote.map((r) => r.pubkey))].filter(
		(p) => p && !cache.has(p),
	)
	if (missing.length > 0) {
		const profiles = userProfiles(config, missing)
		for (const p of missing) cache.set(p, profiles.get(p) || '')
	}
	for (const r of remote) {
		const name = cache.get(r.pubkey)
		if (name) r.author = name
	}
	return remote
}

/**
 * Render an incoming relay message as it appears in the Amp transcript.
 * Rendered as `<author>: <content>` with a leading zero-width space — an
 * invisible marker agent.start uses to recognize plugin-appended messages
 * and cancel their turn (the TUI already labels them "Sent by plugin").
 */
export const INCOMING_MARK = '\u200b'

export function formatIncoming(m: RemoteMessage): string {
	return `${INCOMING_MARK}${m.author}: ${truncate(m.content, 4000)}`.trim()
}

/**
 * Matches the formatIncoming shape — fallback detection across plugin
 * reloads. Also still matches the older `[buzz]`- and 💬-prefixed shapes.
 */
export const INCOMING_RE = /^(?:\u200b|\[buzz\] |💬 ).{1,80}?: /s

/**
 * Render a relay message that should dispatch a real agent turn (an
 * authorized sender mentioned the agent). Same visible `<author>: <content>`
 * shape as formatIncoming, but marked with an invisible word joiner so
 * agent.start lets the turn run while still skipping the mirror-back.
 */
export const TRIGGER_MARK = '\u2060'

export function formatTrigger(m: RemoteMessage): string {
	return `${TRIGGER_MARK}${m.author}: ${truncate(m.content, 4000)}`.trim()
}

/** Matches the formatTrigger shape — fallback detection across plugin reloads. */
export const TRIGGER_RE = /^\u2060.{1,80}?: /s

/**
 * Whether a relay sender is allowed to trigger an agent turn by mentioning
 * the agent: the plugin owner, a channel owner/admin, or an explicitly
 * configured trigger pubkey.
 */
export function senderMayTrigger(
	config: BuzzConfig,
	senderPubkey: string,
	members: Array<{ pubkey: string; role?: string }>,
): boolean {
	if (!senderPubkey) return false
	if (senderPubkey === config.userPubkey) return true
	if (config.triggerPubkeys.includes(senderPubkey)) return true
	const role = members.find((m) => m.pubkey === senderPubkey)?.role
	return role === 'owner' || role === 'admin'
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

const CHAT_AGENT_NAME = 'buzz-chat'

export default function (amp: PluginAPI) {
	const config = loadConfig()
	if (!config) {
		amp.logger.log(
			'amp-buzz: no relay configured (set BUZZ_RELAY_URL and BUZZ_PRIVATE_KEY); plugin is inert',
		)
		return
	}
	amp.logger.log(`amp-buzz: mirroring threads to ${config.relayUrl}`)

	// "buzz chat" mode: Tab to it, type, and the message posts straight to the
	// thread's Buzz channel. The turn is cancelled in agent.start, so this
	// agent never actually runs inference.
	const chatAgent = amp.createAgent({
		name: CHAT_AGENT_NAME,
		model: 'anthropic/claude-haiku-4-5-20251001',
		instructions:
			'You never run. Messages submitted in this mode are posted to the Buzz channel mirroring this thread, and the turn is cancelled before inference.',
		tools: { include: [] },
		display: { label: 'buzz chat', color: '#f5a623' },
	})
	amp.registerAgentMode({
		key: 'buzz-chat',
		label: 'buzz chat',
		description: "Post messages to this thread's Buzz channel instead of prompting the agent",
		agent: chatAgent.definition,
	})

	/** Ensure a session channel exists for a thread, creating it (and the session's own agent identity) from the given text. */
	function ensureSession(
		threadId: string,
		firstText: string,
	): { state: SessionState; agent: AgentIdentity; created: boolean } {
		let state = loadSession(threadId)
		if (state && state.channel_id) {
			return { state, agent: sessionAgent(config!, threadId, state), created: false }
		}
		const agent = createSessionAgent(config!, threadId)
		const channel = createSessionChannel(config!, agent, threadId, firstText)
		state = {
			channel_id: channel.id,
			channel_name: channel.name,
			created_at: Math.floor(Date.now() / 1000),
			last_seen: Math.floor(Date.now() / 1000) - 5,
			seen_event_ids: [],
			user_is_member: false,
			agent: {
				seckey: agent.seckey,
				pubkey: agent.pubkey,
				auth_tag: agent.authTag,
				name: agent.name,
			},
		}
		saveSession(threadId, state)
		return { state, agent, created: true }
	}

	// Event IDs this plugin published itself (mirrored prompts, chat posts):
	// the poller must not echo them back into the transcript. Also persisted
	// in seen_event_ids so the exclusion survives plugin reloads.
	const ownEventIds = new Set<string>()
	const nameCache = new Map<string, string>()

	function recordOwnEvent(threadId: string, state: SessionState, res: any): void {
		const id = res && !res.error && typeof res.event_id === 'string' ? res.event_id : null
		if (!id) return
		ownEventIds.add(id)
		state.seen_event_ids = [...(state.seen_event_ids || []), id].slice(-300)
		saveSession(threadId, state)
	}

	/**
	 * Context blurb teaching the agent its own relay identity, so it can
	 * recognize channel messages addressed to it.
	 */
	function relayIdentityNote(agent: AgentIdentity, channelName: string): string {
		const name = agent.name
		return (
			`Buzz relay context: this thread is mirrored to Buzz channel #${channelName}. ` +
			`Your identity on the relay is "${name}" (pubkey ${agent.pubkey}). ` +
			`Each Amp session has its own relay identity, so other "Amp (…)"-named users ` +
			`on the channel are different sessions — treat them as separate collaborators, not as yourself. ` +
			`Channel messages appear in this thread as "<author>: …" lines; ` +
			`messages mentioning "@${name}" are directed at you. ` +
			`To get another user's or agent's attention on the channel you MUST @-mention them ` +
			`by their display name (e.g. "@joah") — untagged messages are ambient and may go unread. ` +
			`Mentions notify people and can dispatch agent turns, so ONLY @-mention someone when ` +
			`you actually need their attention; otherwise write names without the @.`
		)
	}

	/**
	 * Post chat text to the thread's channel: under the user's key where the
	 * user is a member, otherwise under the agent key with a name prefix
	 * (plugin-created channels never include the user).
	 */
	function postChat(threadId: string, text: string): SessionState {
		const { state, agent } = ensureSession(threadId, text)
		const sent =
			state.user_is_member === false
				? buzzSend(
						config!,
						agentIdentity(agent),
						state.channel_id,
						`${ownerName(config!)}: ${text}`,
					)
				: buzzSend(config!, { seckey: config!.userSeckey }, state.channel_id, text)
		recordOwnEvent(threadId, state, sent)
		return state
	}

	// -------------------------------------------------------------------
	// Live incoming messages: poll watched threads and append new channel
	// messages (remote collaborators and the user's own Buzz-native posts)
	// straight into the Amp chat transcript. Each append starts a turn.
	// Messages from authorized senders that @-tag the agent dispatch a real
	// turn (agent.start skips only the mirror-back); everything else is
	// recognized (via `appendedRelay` or the message shape) and cancelled —
	// visible in the chat and thread history for the next real turn, but
	// never dispatching inference by itself. Events this plugin published
	// (mirrored prompts, chat posts) never come back at all: they are
	// excluded by `ownEventIds` and the persisted seen set, so Amp-sent
	// messages cannot trigger turns.
	// -------------------------------------------------------------------
	const watchedThreads = new Set<ThreadID>()
	const appendedRelay = new Set<string>()
	const triggerRelay = new Set<string>()
	let polling = false

	async function pollOnce() {
		if (polling) return
		polling = true
		try {
			for (const threadId of watchedThreads) {
				try {
					const state = loadSession(threadId)
					if (!state || !state.channel_id) continue
					const agent = sessionAgent(config!, threadId, state)
					const remote = fetchRemoteMessages(config!, agent, state, { ownEventIds, nameCache })
					saveSession(threadId, state)
					let members: Array<{ pubkey: string; role?: string }> | null = null
					for (const m of remote) {
						let trigger = false
						if (m.mentions_agent) {
							members ??= channelMembers(config!, state.channel_id, agentIdentity(agent))
							trigger = senderMayTrigger(config!, m.pubkey, members)
						}
						const text = trigger ? formatTrigger(m) : formatIncoming(m)
						const set = trigger ? triggerRelay : appendedRelay
						set.add(text)
						try {
							await amp.threads
								.get(threadId)
								.appendUserMessage({ type: 'user-message', content: text })
						} catch (err) {
							set.delete(text)
							logError('poll.append', err)
							void amp.ui
								.notify(`#${state.channel_name} · ${m.author}: ${truncate(m.content, 300)}`)
								.catch(() => {})
						}
					}
				} catch (err) {
					logError('poll', err)
				}
			}
		} finally {
			polling = false
		}
	}

	const pollTimer = setInterval(() => void pollOnce(), 10_000)
	if (typeof pollTimer.unref === 'function') pollTimer.unref()
	amp.onDispose(() => clearInterval(pollTimer))

	amp.on('session.start', (event) => {
		if (loadSession(event.thread.id)) watchedThreads.add(event.thread.id)
	})

	amp.on('agent.start', async (event: AgentStartEvent, ctx) => {
		try {
			const prompt = (event.message || '').trim()
			if (!prompt) return {}

			// A relay message from an authorized sender that mentions the
			// agent: let the turn dispatch, but skip mirroring — the message
			// already lives on the relay. The reply mirrors via agent.end.
			if (triggerRelay.has(prompt) || TRIGGER_RE.test(prompt)) {
				triggerRelay.delete(prompt)
				watchedThreads.add(event.thread.id)
				const state = loadSession(event.thread.id)
				if (state) {
					const agent = sessionAgent(config, event.thread.id, state)
					return {
						message: { content: relayIdentityNote(agent, state.channel_name), display: false },
					}
				}
				return {}
			}

			// A relay message the poller appended into the transcript: it is
			// already visible and already lives on the relay — just prevent
			// the turn (no inference, no mirroring).
			if (appendedRelay.has(prompt) || INCOMING_RE.test(prompt)) {
				appendedRelay.delete(prompt)
				await ctx.thread.cancel()
				return {}
			}

			// Buzz chat mode: post to the channel and cancel the turn.
			let isChatMode = false
			try {
				const threadAgent = await ctx.thread.agent()
				const def = threadAgent.definition
				isChatMode = def.kind === 'agent-definition' && def.name === CHAT_AGENT_NAME
			} catch {
				// agent lookup unavailable; fall through to normal handling
			}
			// A leading backslash in any mode is a chat escape too (`\lunch?`
			// posts "lunch?"). Backslash instead of `//` because Amp's
			// slash-command UI captures a leading `/`.
			const chatEscape = prompt.startsWith('\\') ? prompt.replace(/^\\+/, '').trim() : null
			if (isChatMode || chatEscape) {
				const text = isChatMode ? prompt : chatEscape!
				if (text) {
					const state = postChat(event.thread.id, text)
					watchedThreads.add(event.thread.id)
					void ctx.ui.notify(`→ #${state.channel_name}`).catch(() => {})
				}
				await ctx.thread.cancel()
				return {}
			}

			const { state, agent, created: firstPrompt } = ensureSession(event.thread.id, prompt)
			watchedThreads.add(event.thread.id)

			const sent = mirrorPrompt(config, agent, state, prompt)
			recordOwnEvent(event.thread.id, state, sent)

			if (firstPrompt) {
				return {
					message: {
						content:
							`This thread is now mirrored to Buzz channel #${state.channel_name} on ${config.relayUrl}. ` +
							`Your replies are published there under the thread's agent identity; remote collaborators may join and post — ` +
							`their messages appear directly in this thread, attributed to their authors. ` +
							relayIdentityNote(agent, state.channel_name),
						display: false,
					},
				}
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
			const agent = sessionAgent(config, event.thread.id, state)
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
				const lines = [`Relay: ${config.relayUrl}`, `Your pubkey: ${config.userPubkey}`]
				const state = ctx.thread ? loadSession(ctx.thread.id) : null
				if (state && ctx.thread) {
					const agent = sessionAgent(config, ctx.thread.id, state)
					lines.push(
						`Session agent: ${agent.name} — ${agent.pubkey} (${bech32Encode('npub', Buffer.from(agent.pubkey, 'hex'))})`,
						`This thread → channel #${state.channel_name} (${state.channel_id})`,
					)
				} else {
					lines.push(
						'This thread is not mirrored yet (the channel and its session agent identity are created on your first prompt).',
					)
				}
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
			description: "Search relay users by name (or paste a pubkey) and add them to this thread's Buzz channel",
		},
		async (ctx) => {
			try {
				const state = ctx.thread ? loadSession(ctx.thread.id) : null
				if (!state) {
					await ctx.ui.notify('This thread has no Buzz channel yet — send a prompt first.')
					return
				}
				const raw = (
					(await ctx.ui.input({
						title: 'Invite to Buzz channel',
						helpText: 'name to search, hex pubkey, or npub1…',
					})) || ''
				).trim()
				if (!raw) return

				let pubkey: string | null = null
				let label = ''
				try {
					pubkey = normalizePublicKey(raw)
				} catch {
					// not a key — search the relay by name
				}
				if (!pubkey) {
					const matches = searchUsers(config, raw)
					if (matches.length === 0) {
						await ctx.ui.notify(`No relay users matching “${raw}”`)
						return
					}
					const options = matches.map((u) => `${u.display_name} (${u.pubkey.slice(0, 12)}…)`)
					let chosen: string | undefined = options[0]
					if (matches.length > 1) {
						chosen = await ctx.ui.select({
							title: `Invite to #${state.channel_name}`,
							options,
						})
					}
					const idx = chosen ? options.indexOf(chosen) : -1
					if (idx === -1) return
					pubkey = matches[idx].pubkey
					label = matches[idx].display_name
				}

				// Plugin-created channels are owned by the session agent, so
				// the add must be signed by it; /join-ed and legacy channels
				// are administered by the user's key.
				const inviter =
					state.user_is_member === false && ctx.thread
						? agentIdentity(sessionAgent(config, ctx.thread.id, state))
						: { seckey: config.userSeckey }
				buzz(config, inviter, [
					'channels',
					'add-member',
					'--channel',
					state.channel_id,
					'--pubkey',
					pubkey,
					'--role',
					'member',
				])
				await ctx.ui.notify(`Added ${label || pubkey.slice(0, 8) + '…'} to #${state.channel_name}`)
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
				if (!content || !ctx.thread) return
				postChat(ctx.thread.id, content)
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
				if (!state || !ctx.thread) {
					await ctx.ui.notify('This thread has no Buzz channel yet — send a prompt first.')
					return
				}
				const agent = sessionAgent(config, ctx.thread.id, state)
				// Peek without advancing the cursor so the poller still appends
				// these messages into the chat transcript.
				const peek: SessionState = { ...state, seen_event_ids: [...state.seen_event_ids] }
				const remote = fetchRemoteMessages(config, agent, peek, { ownEventIds, nameCache })
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

	amp.registerCommand(
		'join',
		{
			title: 'Join channel',
			category: 'Buzz',
			description: 'Join an existing Buzz channel in a new thread, importing its history',
		},
		async (ctx) => {
			try {
				const query = await ctx.ui.input({
					title: 'Join a Buzz channel',
					helpText: 'search channels by name or description (empty lists all)…',
				})
				if (query === null || query === undefined) return
				const channels = listChannels(config, query)
				if (channels.length === 0) {
					await ctx.ui.notify(`No channels matching “${query}”`)
					return
				}
				const shown = channels.slice(0, 50)
				const options = shown.map((c) =>
					c.description ? `#${c.name} — ${truncate(c.description, 80)}` : `#${c.name}`,
				)
				let chosen: string | undefined = options[0]
				if (shown.length > 1) {
					chosen = await ctx.ui.select({
						title: `Join channel (${channels.length} match${channels.length === 1 ? '' : 'es'})`,
						options,
					})
				}
				const idx = chosen ? options.indexOf(chosen) : -1
				if (idx === -1) return
				const channel = shown[idx]

				buzz(config, { seckey: config.userSeckey }, ['channels', 'join', '--channel', channel.channel_id], {
					allowFailure: true,
				})

				const history = fetchChannelHistory(config, channel.channel_id)
				const missing = [...new Set(history.map((m) => m.pubkey))].filter(
					(p) => p && !nameCache.has(p),
				)
				if (missing.length > 0) {
					const profiles = userProfiles(config, missing)
					for (const p of missing) nameCache.set(p, profiles.get(p) || '')
				}

				const thread = await amp.getBuiltinAgent('medium').createThread({ show: true })
				// This session gets its own agent identity, added to the channel
				// as a bot so it can publish replies there.
				const agent = createSessionAgent(config, thread.id)
				buzz(
					config,
					{ seckey: config.userSeckey },
					[
						'channels',
						'add-member',
						'--channel',
						channel.channel_id,
						'--pubkey',
						agent.pubkey,
						'--role',
						'bot',
					],
					{ allowFailure: true },
				)
				const now = Math.floor(Date.now() / 1000)
				const newest = history.length > 0 ? history[history.length - 1].created_at : now
				const state: SessionState = {
					channel_id: channel.channel_id,
					channel_name: channel.name,
					created_at: now,
					last_seen: newest,
					seen_event_ids: history.slice(-300).map((m) => m.id),
					user_is_member: true,
					agent: {
						seckey: agent.seckey,
						pubkey: agent.pubkey,
						auth_tag: agent.authTag,
						name: agent.name,
					},
				}
				saveSession(thread.id, state)
				watchedThreads.add(thread.id)

				const named = history.map((m) => ({
					author: nameCache.get(m.pubkey) || (m.pubkey ? m.pubkey.slice(0, 8) : 'unknown'),
					content: m.content,
				}))
				const blocks = [
					INCOMING_MARK + relayIdentityNote(agent, channel.name),
					...formatHistoryBlocks(named),
				]
				for (const block of blocks) {
					appendedRelay.add(block)
					try {
						await thread.appendUserMessage({ type: 'user-message', content: block })
					} catch (err) {
						appendedRelay.delete(block)
						logError('command.join.append', err)
					}
				}
				await ctx.ui.notify(
					`Joined #${channel.name}` +
						(history.length > 0 ? ` — imported ${history.length} messages` : ''),
				)
			} catch (err) {
				logError('command.join', err)
				await ctx.ui.notify(`Join failed: ${err instanceof Error ? err.message : err}`)
			}
		},
	)
}
