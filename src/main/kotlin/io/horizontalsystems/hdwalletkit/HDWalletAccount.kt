package io.horizontalsystems.hdwalletkit

import io.horizontalsystems.hdwalletkit.HDWallet.Chain

class HDWalletAccount(
    accountPrivateKey: HDKey
) {
    private val hdKeychain: HDKeychain = HDKeychain(accountPrivateKey)

    fun privateKey(index: Int, chain: Chain): HDKey {
        return hdKeychain.getKeyByPath("${chain.ordinal}/$index")
    }

    fun privateKey(path: String): HDKey {
        return hdKeychain.getKeyByPath(path)
    }

    fun publicKey(index: Int, chain: Chain): HDPublicKey {
        return HDPublicKey(key = privateKey(index, chain))
    }

    fun publicKeys(indices: IntRange, chain: Chain): List<HDPublicKey> {
        val parentPrivateKey = privateKey("${chain.ordinal}")
        return hdKeychain.deriveNonHardenedChildKeys(parentPrivateKey, indices).map {
            HDPublicKey(it)
        }
    }
}
