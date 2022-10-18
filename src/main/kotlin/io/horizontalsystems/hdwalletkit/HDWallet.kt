package io.horizontalsystems.hdwalletkit

class HDWallet(seed: ByteArray, private val coinType: Int, val gapLimit: Int = 20, val purpose: Purpose = Purpose.BIP44) {

    enum class Chain {
        EXTERNAL, INTERNAL
    }

    enum class Purpose(
        val value: Int,
        val pubAddressType: List<PublicAddressType> // format [mainNetType, testNetType]
    ) {
        BIP44(44, listOf(PublicAddressType.P2PKH, PublicAddressType.TEST_P2PKH)),
        BIP49(49, listOf(PublicAddressType.P2WPKH_P2SH, PublicAddressType.TEST_P2WPKH_P2SH)),
        BIP84(84, listOf(PublicAddressType.P2WPKH, PublicAddressType.TEST_P2WPKH));
    }

    private val hdKeychain: HDKeychain = HDKeychain(seed)

    // m / purpose' / coin_type' / account' / change / address_index
    //
    // Purpose is a constant set to 44' (or 0x8000002C) following the BIP43 recommendation.
    // It indicates that the subtree of this node is used according to this specification.
    // Hardened derivation is used at this level.

    // One master node (seed) can be used for unlimited number of independent cryptocoins such as Bitcoin, Litecoin or Namecoin. However, sharing the same space for various cryptocoins has some disadvantages.
    // This level creates a separate subtree for every cryptocoin, avoiding reusing addresses across cryptocoins and improving privacy issues.
    // Coin type is a constant, set for each cryptocoin. Cryptocoin developers may ask for registering unused number for their project.
    // The list of already allocated coin types is in the chapter "Registered coin types" below.
    // Hardened derivation is used at this level.
    // network.name == MainNet().name ? 0 : 1
    // private var coinType: Int = 0

    fun hdPublicKey(account: Int, index: Int, external: Boolean): HDPublicKey {
        return HDPublicKey(index = index, external = external, key = privateKey(account = account, index = index, chain = if (external) 0 else 1))
    }

    fun hdPublicKeys(account: Int, indices: IntRange, external: Boolean): List<HDPublicKey> {
        val parentPrivateKey = privateKey("m/${purpose.value}'/$coinType'/$account'/${if (external) 0 else 1}") // todo: this may be a bug they are missing the last ' in the path same for others below
        return hdKeychain
            .deriveNonHardenedChildKeys(parentPrivateKey, indices)
            .map {
                HDPublicKey(it.childNumber, external, it)
            }
    }

    fun receiveHDPublicKey(account: Int, index: Int): HDPublicKey {
        return HDPublicKey(index = index, external = true, key = privateKey(account = account, index = index, chain = 0))
    }

    fun changeHDPublicKey(account: Int, index: Int): HDPublicKey {
        return HDPublicKey(index = index, external = false, key = privateKey(account = account, index = index, chain = 1))
    }

    fun privateKey(account: Int, index: Int, chain: Int): HDKey {
        return privateKey(path = "m/${purpose.value}'/$coinType'/$account'/$chain/$index")
    }

    fun privateKey(account: Int, index: Int, external: Boolean): HDKey {
        return privateKey(account, index, if (external) Chain.EXTERNAL.ordinal else Chain.INTERNAL.ordinal)
    }

    fun privateKey(path: String): HDKey {
        return hdKeychain.getKeyByPath(path)
    }

    fun masterPublicKey(mainNet: Boolean = true): String {
        return hdKeychain.getKeyByPath("m/${purpose.value}'/$coinType'/0'").serializePubB58(purpose, if(mainNet) purpose.pubAddressType[0] else purpose.pubAddressType[1])
    }
}
