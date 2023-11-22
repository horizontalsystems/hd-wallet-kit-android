package io.horizontalsystems.hdwalletkit

import io.horizontalsystems.hdwalletkit.HDWallet.Chain

class HDWalletAccount(
    accountPrivateKey: HDKey,
    curve: Curve = Curve.Secp256K1
) {
    private val hdKeychain: HDKeychain = HDKeychain(accountPrivateKey, curve)

    fun privateKey(index: Int, chain: Chain): HDKey = when (hdKeychain.curve) {
            Curve.Ed25519 -> throw CantDeriveNonHardened()
            Curve.Secp256K1 -> hdKeychain.getKeyByPath("${chain.ordinal}/$index")
        }

    fun privateKey(path: String): HDKey {
        return hdKeychain.getKeyByPath(path)
    }

    fun publicKey(index: Int, chain: Chain): HDPublicKey = when (hdKeychain.curve) {
        Curve.Ed25519 -> throw CantDeriveNonHardened()
        Curve.Secp256K1 -> HDPublicKey(key = privateKey(index, chain))
    }

    fun publicKeys(indices: IntRange, chain: Chain): List<HDPublicKey> = when (hdKeychain.curve) {
        Curve.Ed25519 -> throw CantDeriveNonHardened()
        Curve.Secp256K1 -> {
            val parentPrivateKey = privateKey("${chain.ordinal}")
            hdKeychain.deriveNonHardenedChildKeys(parentPrivateKey, indices).map {
                HDPublicKey(it)
            }
        }
    }
}
