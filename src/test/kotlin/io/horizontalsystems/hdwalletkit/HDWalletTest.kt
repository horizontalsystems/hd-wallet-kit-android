package io.horizontalsystems.hdwalletkit

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test

class HDWalletTest {

    private val seed = "6908630f564bd3ca9efb521e72da86727fc78285b15decedb44f40b02474502ed6844958b29465246a618b1b56b4bdffacd1de8b324159e0f7f594c611b0519d".hexStringToByteArray()
    private val hdWalletMainNet = HDWallet(seed, 0)
    private val hdWalletTestNet = HDWallet(seed, 1)

    @Test
    fun receiveAddress_correctAddress_mainNet() {
        val hdPublicKey = hdWalletMainNet.receiveHDPublicKey(0, 0)

        assertEquals("031f4e92f8d1f78d8a149863415690b2c2845fcae3be009f9d55595e4edc00e2ea", hdPublicKey.publicKey.toHexString())
    }

    @Test
    fun receiveAddress_correctAddress_testNet() {
        val hdPublicKey = hdWalletTestNet.receiveHDPublicKey(0, 0)

        assertEquals("035e028c6d6b0f18d31d699957f219e75415c2f5dea979f3f4771e11954ec77c13", hdPublicKey.publicKey.toHexString())
    }

    @Test
    fun changeAddress_correctAddress_testNet() {
        val hdPublicKey = hdWalletTestNet.changeHDPublicKey(0, 0)

        assertEquals("03c9e21dfac7bdc98696f1bedb4efb64c362d96654f33ce8b0d69d6c0940fdef6b", hdPublicKey.publicKey.toHexString())
    }

    @Test
    fun changeAddress_correctPublicKey() {
        val hdPublicKey = hdWalletMainNet.changeHDPublicKey(0, 0)

        assertEquals("0301aeeb78a8ee9201659fcbe8d78e73205e7b26e0e46608e2a661aabe87822ce5", hdPublicKey.publicKey.toHexString())
    }

    @Test
    fun privateKey() {
        val hdKey1 = hdWalletMainNet.privateKey(0, 0, 0)
        val hdKey2 = hdWalletMainNet.privateKey(0, 0, true)

        assertArrayEquals(hdKey1.chainCode, hdKey2.chainCode)
    }

    @Test
    fun testBatchPublicKeysGeneration() {
        val publicKeys = mutableListOf<HDPublicKey>()

        for (i in 0 until 10) {
            publicKeys.add(hdWalletMainNet.hdPublicKey(0, i, true))
        }

        val batchPublicKeys = hdWalletMainNet.hdPublicKeys(0, 0 until 10, true)

        assert(publicKeys.size == batchPublicKeys.size)

        publicKeys.forEachIndexed { index, pubKey ->
            assertArrayEquals(pubKey.publicKey, batchPublicKeys[index].publicKey)
        }
    }

}
