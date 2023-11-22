package io.horizontalsystems.hdwalletkit

import java.math.BigInteger

sealed class Curve {
    object Secp256K1 : Curve()
    object Ed25519 : Curve()

    val beep32SeedSalt: String
        get() = when (this) {
            is Ed25519 -> "ed25519 seed"
            is Secp256K1 -> "Bitcoin seed"
        }

    fun applyParameters(parent: HDKey, childKey: ByteArray): BigInteger {
        val ilInt = BigInteger(1, childKey)
        return when (this) {
            Ed25519 -> {
                ilInt
            }
            Secp256K1 -> {
                if (ilInt >= ECKey.ecParams.n) {
                    throw HDDerivationException("Derived private key is not less than N")
                }
                val ki = parent.getPrivKey().add(ilInt).mod(ECKey.ecParams.n)
                if (ki.signum() == 0) {
                    throw HDDerivationException("Derived private key is zero")
                }
                ki
            }
        }
    }

    val supportNonHardened: Boolean
        get() = when (this) {
            is Ed25519 -> false
            is Secp256K1 -> true
        }
}

