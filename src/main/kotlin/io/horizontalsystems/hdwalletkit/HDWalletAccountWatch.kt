package io.horizontalsystems.hdwalletkit

import io.horizontalsystems.hdwalletkit.HDWallet.Chain

class HDWalletAccountWatch(
    accountPublicKey: HDKey,
    curve: Curve = Curve.Secp256K1
) {
    private val hdKeychain: HDKeychain = HDKeychain(accountPublicKey, curve)

    fun publicKey(index: Int, chain: Chain): HDPublicKey {
        return HDPublicKey(hdKeychain.getKeyByPath("${chain.ordinal}/$index"))
    }

    fun publicKeys(indices: IntRange, chain: Chain): List<HDPublicKey> {
        require(indices.first < 0x80000000 && indices.last < 0x80000000) {
            "Derivation error: Can't derive hardened children from public key"
        }

        val parentPublicKey = hdKeychain.getKeyByPath("${chain.ordinal}")
        return hdKeychain.deriveNonHardenedChildKeys(parentPublicKey, indices)
            .map {
                HDPublicKey(it)
            }
    }
}
