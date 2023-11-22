package io.horizontalsystems.hdwalletkit

class HDWallet(
    private val hdKeychain: HDKeychain,
    private val coinType: Int,
    purpose: Purpose
) {

    constructor(
        seed: ByteArray,
        coinType: Int,
        purpose: Purpose,
        curve: Curve = Curve.Secp256K1
    ) : this(
        HDKeychain(seed, curve), coinType, purpose
    )

    constructor(
        masterKey: HDKey,
        coinType: Int,
        purpose: Purpose,
        curve: Curve = Curve.Secp256K1
    ) : this(
        HDKeychain(masterKey, curve), coinType, purpose
    )

    enum class Chain {
        EXTERNAL, INTERNAL
    }

    enum class Purpose(val value: Int) {
        BIP44(44),
        BIP49(49),
        BIP84(84),
        BIP86(86)
    }

    val masterKey: HDKey
        get() = hdKeychain.hdKey

    // m / purpose' / coin_type' / account' / change / address_index
    //
    // Purpose is a constant set to 44' (or 0x8000002C) following the BIP43 recommendation.
    // It indicates that the subtree of this node is used according to this specification.
    // Hardened derivation is used at this level.
    private val purpose: Int = purpose.value

    // One master node (seed) can be used for unlimited number of independent cryptocoins such as Bitcoin, Litecoin or Namecoin. However, sharing the same space for various cryptocoins has some disadvantages.
    // This level creates a separate subtree for every cryptocoin, avoiding reusing addresses across cryptocoins and improving privacy issues.
    // Coin type is a constant, set for each cryptocoin. Cryptocoin developers may ask for registering unused number for their project.
    // The list of already allocated coin types is in the chapter "Registered coin types" below.
    // Hardened derivation is used at this level.
    // network.name == MainNet().name ? 0 : 1
    // private var coinType: Int = 0

    fun hdPublicKey(account: Int, index: Int, external: Boolean): HDPublicKey {
        return HDPublicKey(privateKey(account = account, index = index, chain = if (external) 0 else 1))
    }

    fun hdPublicKeys(account: Int, indices: IntRange, external: Boolean): List<HDPublicKey> {
        val parentPrivateKey =
            privateKey("m/$purpose'/$coinType'/$account'/${if (external) 0 else 1}")
        return hdKeychain.deriveNonHardenedChildKeys(parentPrivateKey, indices).map {
            HDPublicKey(it)
        }
    }

    fun receiveHDPublicKey(account: Int, index: Int): HDPublicKey {
        return HDPublicKey(privateKey(account = account, index = index, chain = 0))
    }

    fun changeHDPublicKey(account: Int, index: Int): HDPublicKey {
        return HDPublicKey(privateKey(account = account, index = index, chain = 1))
    }

    fun privateKey(account: Int, index: Int, chain: Int): HDKey {
        return privateKey(path = "m/$purpose'/$coinType'/$account'/$chain/$index")
    }

    fun privateKey(account: Int): HDKey {
        return privateKey(path = "m/$purpose'/$coinType'/$account'")
    }

    fun privateKey(account: Int, index: Int, external: Boolean): HDKey {
        return privateKey(
            account, index, if (external) Chain.EXTERNAL.ordinal else Chain.INTERNAL.ordinal
        )
    }

    fun privateKey(path: String): HDKey {
        return hdKeychain.getKeyByPath(path)
    }

}
