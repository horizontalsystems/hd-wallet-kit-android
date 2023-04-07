package io.horizontalsystems.hdwalletkit

import org.junit.Assert
import org.junit.Test

class TaprootTest {

    @Test()
    fun addressGeneration() {
        val xPrivKey =
            HDExtendedKey("xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu")
        Assert.assertEquals(
            "xpub661MyMwAqRbcFkPHucMnrGNzDwb6teAX1RbKQmqtEF8kK3Z7LZ59qafCjB9eCRLiTVG3uxBxgKvRgbubRhqSKXnGGb1aoaqLrpMBDrVxga8",
            xPrivKey.serializePublic()
        )

        val hdWallet = HDWallet(xPrivKey.key, 0, HDWallet.Purpose.BIP86)

        // Account 0, root = m/86'/0'/0'
        val privateKey = hdWallet.privateKey("m/86'/0'/0'")
        Assert.assertEquals(
            "xprv9xgqHN7yz9MwCkxsBPN5qetuNdQSUttZNKw1dcYTV4mkaAFiBVGQziHs3NRSWMkCzvgjEe3n9xV8oYywvM8at9yRqyaZVz6TYYhX98VjsUk",
            privateKey.serializePrivate(HDExtendedKeyVersion.xprv.value)
        )
        Assert.assertEquals(
            "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
            privateKey.serializePublic(HDExtendedKeyVersion.xpub.value)
        )

        // Account 0, first receiving address = m/86'/0'/0'/0/0
        val firstReceivePrivKey = hdWallet.privateKey(0, 0, 0)
        //xprv
        Assert.assertEquals(
            "xprvA449goEeU9okwCzzZaxiy475EQGQzBkc65su82nXEvcwzfSskb2hAt2WymrjyRL6kpbVTGL3cKtp9herYXSjjQ1j4stsXXiRF7kXkCacK3T",
            firstReceivePrivKey.serializePrivate(HDExtendedKeyVersion.xprv.value)
        )
        //xpub
        Assert.assertEquals(
            "xpub6H3W6JmYJXN49h5TfcVjLC3onS6uPeUTTJoVvRC8oG9vsTn2J8LwigLzq5tHbrwAzH9DGo6ThGUdWsqce8dGfwHVBxSbixjDADGGdzF7t2B",
            firstReceivePrivKey.serializePublic(HDExtendedKeyVersion.xpub.value)
        )
        //internal_key
        Assert.assertEquals(
            "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
            firstReceivePrivKey.pubKeyXCoord.toHexString()
        )
        //output_key
        Assert.assertEquals(
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
            firstReceivePrivKey.tweakedOutputKey.pubKeyXCoord.toHexString()
        )
        val firstReceivePubKey = ECKey.fromPublicOnly(firstReceivePrivKey.pubKey)
        Assert.assertEquals(
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
            firstReceivePubKey.tweakedOutputKey.pubKeyXCoord.toHexString()
        )

        // Account 0, second receiving address = m/86'/0'/0'/0/1

        val secondReceivePrivKey = hdWallet.privateKey(0, 1, 0)
        //xprv
        Assert.assertEquals(
            "xprvA449goEeU9okyiF1LmKiDaTgeXvmh87DVyRd35VPbsSop8n8uALpbtrUhUXByPFKK7C2yuqrB1FrhiDkEMC4RGmA5KTwsE1aB5jRu9zHsuQ",
            secondReceivePrivKey.serializePrivate(HDExtendedKeyVersion.xprv.value)
        )
        //xpub
        Assert.assertEquals(
            "xpub6H3W6JmYJXN4CCKUSnriaiQRCZmG6aq4sCMDqTu1ACyngw7HShf59hAxYjXgKDuuHThVEUzdHrc3aXCr9kfvQvZPit5dnD3K9xVRBzjK3rX",
            secondReceivePrivKey.serializePublic(HDExtendedKeyVersion.xpub.value)
        )
        //internal_key
        Assert.assertEquals(
            "83dfe85a3151d2517290da461fe2815591ef69f2b18a2ce63f01697a8b313145",
            secondReceivePrivKey.pubKeyXCoord.toHexString()
        )
        //output_key
        Assert.assertEquals(
            "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
            secondReceivePrivKey.tweakedOutputKey.pubKeyXCoord.toHexString()
        )
        val secondReceivePubKey = ECKey.fromPublicOnly(secondReceivePrivKey.pubKey)
        Assert.assertEquals(
            "a82f29944d65b86ae6b5e5cc75e294ead6c59391a1edc5e016e3498c67fc7bbb",
            secondReceivePubKey.tweakedOutputKey.pubKeyXCoord.toHexString()
        )

        // Account 0, first change address = m/86'/0'/0'/1/0

        val firstChangePrivKey = hdWallet.privateKey(0, 0, 1)
        //xprv
        Assert.assertEquals(
            "xprvA3Ln3Gt3aphvUgzgEDT8vE2cYqb4PjFfpmbiFKphxLg1FjXQpkAk5M1ZKDY15bmCAHA35jTiawbFuwGtbDZogKF1WfjwxML4gK7WfYW5JRP",
            firstChangePrivKey.serializePrivate(HDExtendedKeyVersion.xprv.value)
        )
        //xpub
        Assert.assertEquals(
            "xpub6GL8SnQwRCGDhB59LEz9HMyM6sRYoByXBzXK3iEKWgCz8XrZNHUzd9L3AUBELW5NzA7dEFvMas1F84TuPH3xqdUA5tumaGWFgihJzWytXe3",
            firstChangePrivKey.serializePublic(HDExtendedKeyVersion.xpub.value)
        )
        //internal_key
        Assert.assertEquals(
            "399f1b2f4393f29a18c937859c5dd8a77350103157eb880f02e8c08214277cef",
            firstChangePrivKey.pubKeyXCoord.toHexString()
        )
        //output_key
        Assert.assertEquals(
            "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
            firstChangePrivKey.tweakedOutputKey.pubKeyXCoord.toHexString()
        )
        val firstChangePubKey = ECKey.fromPublicOnly(firstChangePrivKey.pubKey)
        Assert.assertEquals(
            "882d74e5d0572d5a816cef0041a96b6c1de832f6f9676d9605c44d5e9a97d3dc",
            firstChangePubKey.tweakedOutputKey.pubKeyXCoord.toHexString()
        )
    }

}
