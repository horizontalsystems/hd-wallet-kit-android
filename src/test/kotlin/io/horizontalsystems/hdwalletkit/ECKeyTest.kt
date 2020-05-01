package io.horizontalsystems.hdwalletkit

import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets

class ECKeyTest {

    private lateinit var publicKey: ByteArray
    private lateinit var privateKey: BigInteger
    private lateinit var dataToSign: ByteArray
    private lateinit var ecKey: ECKey

    @Before
    fun setUp() {
        // address(P2PKH): 1Ms9Sv1ebeBnoQCSxmwwichbQEaZ5KfXA7
        publicKey = "037d56797fbe9aa506fc263751abf23bb46c9770181a6059096808923f0a64cb15".hexStringToByteArray()
        privateKey = BigInteger("4ee8efccaa04495d5d3ab0f847952fcff43ffc0459bd87981b6be485b92f8d64", 16)
        dataToSign = "01000000019cb78e361651edc22c1c6502961440c139038ca8a8d1696392cd002219d796f2000000001976a914e4de5d630c5cacd7af96418a8f35c411c8ff3c0688acffffffff01c0e4022a010000001976a914e4de5d630c5cacd7af96418a8f35c411c8ff3c0688ac0000000001000000".hexStringToByteArray()
    }

    @Test
    fun createSignature_Success() {
        ecKey = ECKey(publicKey, privateKey, true)

        val expectedSignatureHex = "304402201d914e9d229e4b8cbb7c8dee96f4fdd835cabae7e016e0859c5dc95977b697d50220681395971eecd5df3eb36b8f97f0c8b1a6e98dc7d5662f921e0b2fb0694db0f2"
        val resultSignature = ecKey.createSignature(dataToSign)

        Assert.assertEquals(expectedSignatureHex, resultSignature.toHexString())
    }

    @Test
    fun signMessage() {
        ecKey = ECKey(publicKey, privateKey, true)

        val resultSignature = ecKey.signMessage("abc")
        val expectedSignature = "H5P92Zr8CMBawZmIBknEKYwtiND3f7m4nloz6inU5Yg1NHd3QsZnLGAFi0sn+leQZKYi8dgakcpSsBM3VUOf9lI="

        Assert.assertEquals(expectedSignature, resultSignature)
    }

    @Test
    fun verifySignature() {
        ecKey = ECKey(publicKey, privateKey, true)

        val resultSignature = ecKey.createSignature(dataToSign)
        val verifySignature = ecKey.verifySignature(dataToSign, resultSignature)

        Assert.assertTrue(verifySignature)
    }

    @Test(expected = IllegalStateException::class)
    fun createSignature_NoPrivateKey() {
        ecKey = ECKey(publicKey)

        ecKey.createSignature(dataToSign)
    }

}
