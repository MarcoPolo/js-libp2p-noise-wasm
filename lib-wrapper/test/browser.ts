/* eslint-disable no-console */
/* eslint-env mocha */

import { expect } from 'aegir/chai'
import { duplexPair } from 'it-pair/duplex'
import type { Duplex } from 'it-stream-types'
// import fetch from 'node-fetch'

// import init, { upgrade_outbound, upgrade_inbound } from '../pkg/js_libp2p_noise_wasm.js'
import init, { upgrade_outbound, upgrade_inbound } from 'noise-wasm/js_libp2p_noise_wasm.js'
// // import pkg from '../pkg/js_libp2p_noise_wasm.js'
// // const { upgrade_outbound } = pkg

// async function setup () {
// First up we need to actually load the wasm file, so we use the
// default export to inform it where the wasm file is located on the
// server, and then we wait on the returned promise to wait for the
// wasm to be loaded.
//
// It may look like this: `await init('./pkg/without_a_bundler_bg.wasm');`,
// but there is also a handy default inside `init` function, which uses
// `import.meta` to locate the wasm file relatively to js file.
//
// Note that instead of a string you can also pass in any of the
// following things:
//
// * `WebAssembly.Module`
//
// * `ArrayBuffer`
//
// * `Response`
//
// * `Promise` which returns any of the above, e.g. `fetch("./path/to/wasm")`
//
// This gives you complete control over how the module is loaded
// and compiled.
//
// Also note that the promise, when resolved, yields the wasm module's
// exports which is the same as importing the `*_bg` module in other
// modes

// And afterwards we can use all the functionality defined in wasm.
// const stream = {
//   async write (bytes: any) {
//     console.log('Wrote bytes', bytes)
//   },
//   read () {
//     return new Uint8Array([1, 2, 3, 4, 5])
//   },
//   async read_ready () {

//   }
// }

// console.log(stream)
// const stream = {}
// const duplex = duplexPair()
// await upgrade_outbound(stream)
// await upgrade_inbound(stream)
// }

describe('js-libp2p-noise with wasm', () => {
  before(async () => {
    await init(fetch('./pkg/js_libp2p_noise_wasm_bg.wasm'))
    console.log('Ready')
  })
  it('duplex to stream', async () => {
    const pair = duplexPair<Uint8Array>()
    const duplexTo = pair[0]
    const duplexFrom = pair[1]
    const streamTo = duplexToFFIStream(duplexTo)
    const streamFrom = duplexToFFIStream(duplexFrom)

    const bytesWritten = await streamTo.write(new Uint8Array([1, 2, 3]))
    console.log(bytesWritten)

    expect(bytesWritten).to.equal(3)

    const readBuf = new Uint8Array([0, 0, 0])
    await streamFrom.read_ready()
    const bytesRead = streamFrom.read(readBuf)
    expect(bytesRead).to.equal(3)

    expect(readBuf).to.eql(new Uint8Array([1, 2, 3]))
  })

  it('pair of syncChans', async () => {
    const pair = chanPair()
    const to = pair[0]
    const from = pair[1]
    const streamTo = syncChanToFFIStream(to)
    const streamFrom = syncChanToFFIStream(from)

    const bytesWritten = streamTo.write(new Uint8Array([1, 2, 3]))
    console.log(bytesWritten)

    const readBuf = new Uint8Array([0, 0, 0])
    await streamFrom.read_ready()
    const bytesRead = streamFrom.read(readBuf)
    expect(bytesRead).to.equal(3)
    expect(await bytesWritten).to.equal(3)

    expect(readBuf).to.eql(new Uint8Array([1, 2, 3]))
  })

  it('stream pair', async () => {
    const { readableStream, writableStream } = syncChan()
    const w = writableStream.getWriter()
    const r = readableStream.getReader()

    const val = new Uint8Array([1, 2, 3, 4])

    const writePromise = w.write(val)
    const res = await r.read()
    await writePromise
    expect(res.value).to.eql(val)
  })

  it('handshake', async () => {
    for (let index = 0; index < 20; index++) {
      const pair = chanPair()
      const to = pair[0]
      const from = pair[1]
      const streamTo = syncChanToFFIStream(to)
      const streamFrom = syncChanToFFIStream(from)

      const now = Date.now()

      await Promise.all([
        upgrade_outbound(streamTo),
        upgrade_inbound(streamFrom)
      ])
      console.log('Done with handshake. Took: ', Date.now() - now, 'ms')
    }
  })

  // it('handshake', async () => {
  //   const pair = duplexPair<Uint8Array>()
  //   const duplexTo = pair[0]
  //   const duplexFrom = pair[1]
  //   const streamTo = duplexToFFIStream(duplexTo)
  //   const streamFrom = duplexToFFIStream(duplexFrom)

  //   await Promise.all([
  //     upgrade_outbound(streamTo),
  //     upgrade_inbound(streamFrom)
  //   ])
  //   console.log('Done with handshake')
  // })
})

interface FFIStream {
  write: (buf: Uint8Array) => Promise<number>
  read: (buf: Uint8Array) => number
  read_ready: () => Promise<void>
}

function duplexToFFIStream (duplex: Duplex<Uint8Array>): FFIStream {
  let readInProgress: Uint8Array | null = null
  return {
    async write (buf): Promise<number> {
      // console.log('Wrote', buf, buf.length)
      const val = {
        async * [Symbol.asyncIterator] () {
          yield buf
        }
      }
      try {
        await duplex.sink(val)
      } catch (e) {
        console.error('Failed to write', e)
      }

      return buf.length
    },
    async read_ready (): Promise<void> {
      if (readInProgress === null || readInProgress.length === 0) {
        // @ts-expect-error
        const v: {done: boolean, value: Uint8Array} = await (duplex.source.next())

        if (v.done) {
          // todo don't use an error for this
          throw new Error('Done reading')
        }

        readInProgress = v.value
      }
    },
    read (buf): number {
      if (readInProgress === null) {
        throw new Error('Not ready to read')
      }

      const limit = Math.min(buf.length, readInProgress.length)
      for (let index = 0; index < limit; index++) {
        buf[index] = readInProgress[index]
      }

      readInProgress = readInProgress.slice(limit)
      // console.log('Read', buf, buf.length)
      return limit
    }

  }
}

function syncChanToFFIStream (syncChan: {readableStream: ReadableStream, writableStream: WritableStream}): FFIStream {
  const r = syncChan.readableStream.getReader()
  const w = syncChan.writableStream.getWriter()
  let readInProgress: Uint8Array | null = null
  return {
    async write (buf): Promise<number> {
      await w.ready
      await w.write(buf)
      return buf.length
    },
    async read_ready (): Promise<void> {
      if (readInProgress === null || readInProgress.length === 0) {
        // @ts-expect-error
        const v: {done: boolean, value: Uint8Array} = await r.read()

        if (v.done) {
          // todo don't use an error for this
          throw new Error('Done reading')
        }

        readInProgress = v.value
      }
    },
    read (buf): number {
      if (readInProgress === null) {
        throw new Error('Not ready to read')
      }

      const limit = Math.min(buf.length, readInProgress.length)
      for (let index = 0; index < limit; index++) {
        buf[index] = readInProgress[index]
      }

      readInProgress = readInProgress.slice(limit)
      // console.log('Read', buf, buf.length)
      return limit
    }

  }
}

function chanPair () {
  const a = syncChan()
  const b = syncChan()

  return [
    { readableStream: a.readableStream, writableStream: b.writableStream },
    { readableStream: b.readableStream, writableStream: a.writableStream }
  ]
}

function syncChan () {
  const queueingStrategy = new ByteLengthQueuingStrategy({ highWaterMark: 1 })
  const chunkSize = 16 << 10

  interface QNode {
    buf: ArrayBufferView
    resolve: (size: number) => void
    reject: (err: Error) => void
  }
  interface WriterBlocked {
    resolve: (value: unknown) => void
    reject: (err: Error) => void
  }
  const pendingReads: QNode[] = []
  const pendingWrites: WriterBlocked[] = []

  const writableStream = new WritableStream({
    // Implement the sink
    async write (chunk: ArrayBufferView) {
      let limit = 0
      let chunkBuf
      if (chunk instanceof Uint8Array) {
        chunkBuf = chunk
      } else {
        chunkBuf = new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength)
      }

      // Any pending readers?
      while (chunkBuf.length > 0) {
        while (pendingReads.length === 0) {
          await (new Promise((resolve, reject) => {
            pendingWrites.push({ resolve, reject })
          }))
        }
        // console.log('HERE 4')
        // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        const readNode = (await pendingReads.pop())!
        // console.log('HERE 3')
        let readBuf
        if (readNode.buf instanceof Uint8Array) {
          readBuf = readNode.buf
        } else {
          readBuf = new Uint8Array(readNode.buf.buffer, readNode.buf.byteOffset, readNode.buf.byteLength)
        }

        limit = Math.min(readBuf.length, chunkBuf.length)
        for (let index = 0; index < limit; index++) {
          readBuf[index] = chunkBuf[index]
        }

        chunkBuf = chunkBuf.slice(limit)

        readNode.resolve(limit)
      }
    },
    close () {
      console.error('Not implemented')
    },
    abort (err) {
      console.error('Not implemented')
      console.log('Sink error:', err)
    }
  }, queueingStrategy)

  const readableStream = new ReadableStream({
    // @ts-expect-error – this isn't typed yet https://developer.mozilla.org/en-US/docs/Web/API/ReadableStream/ReadableStream#type
    type: 'bytes',
    autoAllocateChunkSize: chunkSize,
    start (controller) { },
    async pull (controller) {
      // console.log('HERE 5')
      // @ts-expect-error – not typed
      if (controller.byobRequest?.view != null) {
        // console.log('HERE 6')
        // @ts-expect-error – not typed
        const r: ReadableStreamBYOBRequest = controller.byobRequest
        const nPromise: Promise<number> = new Promise((resolve, reject) => {
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          pendingReads.push({ buf: r.view!, resolve, reject })
        })
        if (pendingWrites.length > 0) {
          // Unblock writer
          pendingWrites.pop()?.resolve(undefined)
        }
        // console.log('HERE 1')
        r.respond(await nPromise)
      } else {
        // console.log('HERE 7')
        const buffer = new ArrayBuffer(chunkSize)
        const view = new Uint8Array(buffer)
        const nPromise: Promise<number> = new Promise((resolve, reject) => {
          // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
          pendingReads.push({ buf: view, resolve, reject })
        })
        if (pendingWrites.length > 0) {
          // Unblock writer
          pendingWrites.pop()?.resolve(undefined)
        }
        // console.log('HERE 2')
        controller.enqueue(new Uint8Array(buffer, 0, await nPromise))
      }
    }
  })

  return { readableStream, writableStream }
}
