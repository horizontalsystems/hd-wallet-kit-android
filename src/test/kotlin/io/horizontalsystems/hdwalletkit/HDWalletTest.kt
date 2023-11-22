package io.horizontalsystems.hdwalletkit

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Test
import java.util.Arrays

class HDWalletTest {

    private val seed =
        "6908630f564bd3ca9efb521e72da86727fc78285b15decedb44f40b02474502ed6844958b29465246a618b1b56b4bdffacd1de8b324159e0f7f594c611b0519d".hexStringToByteArray()
    private val hdWalletMainNet = HDWallet(seed, 0, HDWallet.Purpose.BIP44)
    private val hdWalletTestNet = HDWallet(seed, 1, HDWallet.Purpose.BIP44)

    @Test
    fun ed25519PrivKey() {
        val hdWallet = HDWallet(seed, 607, HDWallet.Purpose.BIP44, Curve.Ed25519)
        val privateKey = hdWallet.privateKey(0)

        assertEquals(
            "0b9fe06661fd41af89524e2df5b080580b9599560f6d4106f989ccfa579db412",
            privateKey.privKeyBytes.toHexString()
        )
    }

    @Test
    fun receiveAddress_correctAddress_mainNet() {
        val hdPublicKey = hdWalletMainNet.receiveHDPublicKey(0, 0)

        assertEquals(
            "031f4e92f8d1f78d8a149863415690b2c2845fcae3be009f9d55595e4edc00e2ea",
            hdPublicKey.publicKey.toHexString()
        )
    }

    @Test
    fun receiveAddress_correctAddress_testNet() {
        val hdPublicKey = hdWalletTestNet.receiveHDPublicKey(0, 0)

        assertEquals(
            "035e028c6d6b0f18d31d699957f219e75415c2f5dea979f3f4771e11954ec77c13",
            hdPublicKey.publicKey.toHexString()
        )
    }

    @Test
    fun changeAddress_correctAddress_testNet() {
        val hdPublicKey = hdWalletTestNet.changeHDPublicKey(0, 0)

        assertEquals(
            "03c9e21dfac7bdc98696f1bedb4efb64c362d96654f33ce8b0d69d6c0940fdef6b",
            hdPublicKey.publicKey.toHexString()
        )
    }

    @Test
    fun changeAddress_correctPublicKey() {
        val hdPublicKey = hdWalletMainNet.changeHDPublicKey(0, 0)

        assertEquals(
            "0301aeeb78a8ee9201659fcbe8d78e73205e7b26e0e46608e2a661aabe87822ce5",
            hdPublicKey.publicKey.toHexString()
        )
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

    @Test
    fun hdWalletFromAccountXpub() {
        val hdExtendedKey =
            HDExtendedKey("xpub6CudKadFxkN6jXWcJDJSWzt4tNt86ThhYEjtcTywfD5nsYcySEEhfGugKDLnv14ZDNnYBVbfYXbNvRp8cNNw9JAfoMTeph1BqGWYZA4DBDi")

        val hdWallet = HDWallet(hdExtendedKey.key, 0, HDWallet.Purpose.BIP44)

        val privateKey = hdWallet.privateKey("0/0")

        assertEquals("1KaPvs5y3Fwyg4UvSc7pbvDTjk1BVWKgf9", address(privateKey.pubKeyHash))
        assertEquals(
            "036a62a11fdc05e2cd57b22dd8d0ad4a648bfb1dde857ce6062a5f8c29d7f02d08",
            privateKey.pubKey.toHexString()
        )
        assertEquals(null, wifCompressed(privateKey.privKeyBytes))
    }

    @Test
    fun hdWalletFromAccountXprv() {
        val hdExtendedKey =
            HDExtendedKey("xprv9yvGv56N8NooX3S9CBmS9rwLLM3dgzyrB1pHp5aL6sYozkHptgvT7UbCTuyXF1HUAaPiG24iDBbnp7EQr8eSJkANf9EodqUiATBXrtAAHjj")

        val hdWallet = HDWallet(hdExtendedKey.key, 0, HDWallet.Purpose.BIP44)

        val privateKey = hdWallet.privateKey("0/0")

        assertEquals("1KaPvs5y3Fwyg4UvSc7pbvDTjk1BVWKgf9", address(privateKey.pubKeyHash))
        assertEquals(
            "036a62a11fdc05e2cd57b22dd8d0ad4a648bfb1dde857ce6062a5f8c29d7f02d08",
            privateKey.pubKey.toHexString()
        )
        assertEquals(
            "KwuBXScis8EHY926TzAkByRoTsNQGq5YB4kDwkdieK5oBWWSsUzE",
            wifCompressed(privateKey.privKeyBytes)
        )
    }

    @Test
    fun hdWalletFromRootXprv() {
        val hdExtendedKey =
            HDExtendedKey("yprvABrGsX5C9jantLFKTZNpFi2c6RKLw87EhgjRLMzdbwp5NjLsUR1oC2kte6k5YXy9hsCSSBVUtJL5XKwF1oFrofumWE3rFKRx6drdQQpkcR4")

        val hdWallet = HDWallet(hdExtendedKey.key, 0, HDWallet.Purpose.BIP49)
        val privateKey = hdWallet.privateKey(0, 0, 0)

        assertEquals(
            "022d00ba4f264cd0d103ab4fe68cab0dbfbc7684476ef14feeb8d474408ab320cd",
            privateKey.pubKey.toHexString()
        )
        assertEquals(
            "L3F5WWjTcjPizhYwN9V5HDnHyTnNi5q7BFHWs8McTgdKBHptVAJD",
            wifCompressed(privateKey.privKeyBytes)
        )
    }
    @Test(expected = HDExtendedKey.ParsingError.InvalidChecksum::class)
    fun invalidExtendedKeyChecksum() {
        HDExtendedKey("xprv9yvGv56N8NooX3S9CBmS9rwLLM3dgzyrB1pHp5aL6sYozkHptgvT7UbCTuyXF1HUAaPiG24iDBbnp7EQr8eSJkANf9EodqUiATBXrtAAHjo")
    }

    @Test()
    fun testExtendedKeySerialization() {
        assertEquals(
            "xprv9yvGv56N8NooX3S9CBmS9rwLLM3dgzyrB1pHp5aL6sYozkHptgvT7UbCTuyXF1HUAaPiG24iDBbnp7EQr8eSJkANf9EodqUiATBXrtAAHjj",
            HDExtendedKey("xprv9yvGv56N8NooX3S9CBmS9rwLLM3dgzyrB1pHp5aL6sYozkHptgvT7UbCTuyXF1HUAaPiG24iDBbnp7EQr8eSJkANf9EodqUiATBXrtAAHjj").serialize()
        )
    }

    @Test()
    fun testExtendedKeySerialization2() {
        assertEquals(
            "xpub6CudKadFxkN6jXWcJDJSWzt4tNt86ThhYEjtcTywfD5nsYcySEEhfGugKDLnv14ZDNnYBVbfYXbNvRp8cNNw9JAfoMTeph1BqGWYZA4DBDi",
            HDExtendedKey("xpub6CudKadFxkN6jXWcJDJSWzt4tNt86ThhYEjtcTywfD5nsYcySEEhfGugKDLnv14ZDNnYBVbfYXbNvRp8cNNw9JAfoMTeph1BqGWYZA4DBDi").serialize()
        )
    }

    @Test()
    fun testExtendedKeySerialization3() {
        assertEquals(
            "yprvAJ5nxPMjEWX9Jas5pGu8RaAUjd3nPTLkHXhgDv5Bk7xHPv9rBjk4bdm9GJtskqpe7ZKVuQz6ZWAUjh61xH3xK7QbqTDuSe1iYeybk18HDgQ",
            HDExtendedKey("yprvAJ5nxPMjEWX9Jas5pGu8RaAUjd3nPTLkHXhgDv5Bk7xHPv9rBjk4bdm9GJtskqpe7ZKVuQz6ZWAUjh61xH3xK7QbqTDuSe1iYeybk18HDgQ").serialize()
        )
    }

    @Test()
    fun testExtendedKeySerialization4() {
        assertEquals(
            "ypub6X59Mttd4t5SX4wYvJS8ni7DHetGnv4bekdH2JUoJTVGGiUzjH4K9S5d7a8bDMkqn7cY8zu5q9UDKKZMALo3w1wQ6NhwESGt5AvRZHRDMk6",
            HDExtendedKey("yprvAJ5nxPMjEWX9Jas5pGu8RaAUjd3nPTLkHXhgDv5Bk7xHPv9rBjk4bdm9GJtskqpe7ZKVuQz6ZWAUjh61xH3xK7QbqTDuSe1iYeybk18HDgQ").serializePublic()
        )
    }

    @Test(expected = IllegalStateException::class)
    fun testExtendedKeySerialization5() {
        HDExtendedKey("ypub6X59Mttd4t5SX4wYvJS8ni7DHetGnv4bekdH2JUoJTVGGiUzjH4K9S5d7a8bDMkqn7cY8zu5q9UDKKZMALo3w1wQ6NhwESGt5AvRZHRDMk6").serializePrivate()
    }

    private fun wifCompressed(privateKey: ByteArray?): String? {
        if (privateKey == null) return null

        val addressBytes = byteArrayOf(0x80.toByte()) + privateKey.takeLast(32) + byteArrayOf(0x01.toByte())
        val doubleSHA256 = Utils.doubleDigest(addressBytes)
        val addrChecksum = Arrays.copyOfRange(doubleSHA256, 0, 4)

        return Base58.encode(addressBytes + addrChecksum)
    }

    private fun address(pubKeyHash: ByteArray): String {
        val addressBytes = byteArrayOf(0x00.toByte()) + pubKeyHash
        val doubleSHA256 = Utils.doubleDigest(addressBytes)
        val addrChecksum = Arrays.copyOfRange(doubleSHA256, 0, 4)

        return Base58.encode(addressBytes + addrChecksum)
    }

}
