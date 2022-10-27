import { duplexPair } from 'it-pair/duplex'



describe('libp2p-webtransport', () => {
    it('webtransport connects to go-libp2p', async () => {
        const duplex = duplexPair()

        console.log("HERE", duplex)
    })
})
export { }