import { fixedClock } from '@badge/testkit'
import { describe, expect, it } from 'vitest'
import { kvNonceStore, memoryNonceStore, type AtomicKeyValueStore } from './nonce.js'

describe('memoryNonceStore', () => {
  it('accepts a nonce once and refuses it thereafter', async () => {
    const store = memoryNonceStore({ clock: fixedClock(1000) })
    expect(await store.checkAndRecord('abc', 1060)).toBe(true)
    expect(await store.checkAndRecord('abc', 1060)).toBe(false)
  })

  it('keeps different nonces apart', async () => {
    const store = memoryNonceStore({ clock: fixedClock(1000) })
    expect(await store.checkAndRecord('a', 1060)).toBe(true)
    expect(await store.checkAndRecord('b', 1060)).toBe(true)
  })

  // Retention only has to cover the signature's window: past it, a replay fails
  // on `expires` instead.
  it('forgets a nonce once its signature has expired', async () => {
    const clock = fixedClock(1000)
    const store = memoryNonceStore({ clock })
    expect(await store.checkAndRecord('abc', 1060)).toBe(true)
    clock.set(1061)
    expect(await store.checkAndRecord('abc', 1120)).toBe(true)
  })

  it('prunes expired entries to make room', async () => {
    const clock = fixedClock(1000)
    const store = memoryNonceStore({ clock, maxEntries: 2 })
    await store.checkAndRecord('a', 1010)
    await store.checkAndRecord('b', 1010)
    clock.set(1011)
    await expect(store.checkAndRecord('c', 1100)).resolves.toBe(true)
  })

  /**
   * Evicting a live nonce would let an attacker flood the store to push out a
   * target's nonce and then replay it — a bypass that looks like normal
   * operation. Throwing surfaces as nonce_store_unavailable, which is
   * unverifiable: Badge says it could not check rather than wrongly reporting
   * the request as fresh.
   */
  it('refuses to evict a live nonce when full', async () => {
    const store = memoryNonceStore({ clock: fixedClock(1000), maxEntries: 2 })
    await store.checkAndRecord('a', 2000)
    await store.checkAndRecord('b', 2000)
    await expect(store.checkAndRecord('c', 2000)).rejects.toThrow(/refusing to evict/)
  })

  it('still answers a repeat correctly when full', async () => {
    const store = memoryNonceStore({ clock: fixedClock(1000), maxEntries: 2 })
    await store.checkAndRecord('a', 2000)
    await store.checkAndRecord('b', 2000)
    expect(await store.checkAndRecord('a', 2000)).toBe(false)
  })
})

describe('kvNonceStore', () => {
  const recordingKv = (): AtomicKeyValueStore & { calls: [string, number][] } => {
    const keys = new Set<string>()
    const calls: [string, number][] = []
    return {
      calls,
      async setIfAbsent(key, ttlSeconds) {
        calls.push([key, ttlSeconds])
        if (keys.has(key)) return false
        keys.add(key)
        return true
      },
    }
  }

  it('delegates freshness to the store', async () => {
    const kv = recordingKv()
    const store = kvNonceStore(kv, { clock: fixedClock(1000) })
    expect(await store.checkAndRecord('abc', 1060)).toBe(true)
    expect(await store.checkAndRecord('abc', 1060)).toBe(false)
  })

  it('namespaces keys so nonces cannot collide with other data', async () => {
    const kv = recordingKv()
    await kvNonceStore(kv, { clock: fixedClock(1000) }).checkAndRecord('abc', 1060)
    expect(kv.calls[0]?.[0]).toBe('badge:nonce:abc')
  })

  it('accepts a custom prefix', async () => {
    const kv = recordingKv()
    await kvNonceStore(kv, { prefix: 'x/', clock: fixedClock(1000) }).checkAndRecord('abc', 1060)
    expect(kv.calls[0]?.[0]).toBe('x/abc')
  })

  it('sets a TTL covering the remaining validity window', async () => {
    const kv = recordingKv()
    await kvNonceStore(kv, { clock: fixedClock(1000) }).checkAndRecord('abc', 1060)
    expect(kv.calls[0]?.[1]).toBe(60)
  })

  it('never asks for a non-positive TTL', async () => {
    const kv = recordingKv()
    await kvNonceStore(kv, { clock: fixedClock(2000) }).checkAndRecord('abc', 1060)
    expect(kv.calls[0]?.[1]).toBe(1)
  })

  // A store outage must reach the verifier, which reports it as unverifiable
  // rather than as a replay.
  it('lets a store failure propagate', async () => {
    const broken: AtomicKeyValueStore = {
      setIfAbsent: async () => {
        throw new Error('redis is down')
      },
    }
    await expect(kvNonceStore(broken).checkAndRecord('abc', 1060)).rejects.toThrow('redis is down')
  })
})
