package io.horizontalsystems.hdwalletkit

import io.horizontalsystems.hdwalletkit.HDWallet.Purpose
import java.lang.IllegalStateException
import java.math.BigInteger

enum class HDExtendedKeyVersion(
    val value: Int,
    val base58Prefix: String,
    val purpose: Purpose,
    val extendedKeyCoinType: ExtendedKeyCoinType = ExtendedKeyCoinType.Bitcoin,
    val isPublic: Boolean = false
) {

    // bip44
    xprv(0x0488ade4, "xprv", Purpose.BIP44),
    xpub(0x0488b21e, "xpub", Purpose.BIP44, isPublic = true),

    //bip49
    yprv(0x049d7878, "yprv", Purpose.BIP49),
    ypub(0x049d7cb2, "ypub", Purpose.BIP49, isPublic = true),

    //bip84
    zprv(0x04b2430c, "zprv", Purpose.BIP84),
    zpub(0x04b24746, "zpub", Purpose.BIP84, isPublic = true),


    // litecoin bip44
    Ltpv(0x019d9cfe, "Ltpv", Purpose.BIP44, ExtendedKeyCoinType.Litecoin),
    Ltub(0x019da462, "Ltub", Purpose.BIP44, ExtendedKeyCoinType.Litecoin, isPublic = true),


    // litecoin bip49
    Mtpv(0x01b26792, "Mtpv", Purpose.BIP49, ExtendedKeyCoinType.Litecoin),
    Mtub(0x01b26ef6, "Mtub", Purpose.BIP49, ExtendedKeyCoinType.Litecoin, isPublic = true);

    val pubKey: HDExtendedKeyVersion
        get() = when (this) {
            xprv -> xpub
            yprv -> ypub
            zprv -> zpub
            Ltpv -> Ltub
            Mtpv -> Mtub
            xpub, ypub, zpub, Ltub, Mtub -> this
        }

    val privKey: HDExtendedKeyVersion
        get() = when (this) {
            xprv, yprv, zprv, Ltpv, Mtpv -> this
            xpub, ypub, zpub, Ltub, Mtub -> throw IllegalStateException("No privateKey of $base58Prefix")
        }

    companion object {
        fun initFrom(
            purpose: Purpose,
            coinType: ExtendedKeyCoinType,
            isPrivate: Boolean
        ): HDExtendedKeyVersion {
            return when (purpose) {
                Purpose.BIP44 -> {
                    when (coinType) {
                        ExtendedKeyCoinType.Bitcoin -> if (isPrivate) xprv else xpub
                        ExtendedKeyCoinType.Litecoin -> if (isPrivate) Ltpv else Ltub
                    }
                }

                Purpose.BIP49 -> {
                    when (coinType) {
                        ExtendedKeyCoinType.Bitcoin -> if (isPrivate) yprv else ypub
                        ExtendedKeyCoinType.Litecoin -> if (isPrivate) Mtpv else Mtub
                    }
                }

                Purpose.BIP84 -> {
                    if (isPrivate) zprv else zpub
                }
            }
        }

        fun initFrom(prefix: String): HDExtendedKeyVersion? =
            values().firstOrNull { it.base58Prefix == prefix }

        fun initFrom(version: ByteArray): HDExtendedKeyVersion? =
            values().firstOrNull { it.value == BigInteger(version).toInt() }
    }
}

enum class ExtendedKeyCoinType {
    Bitcoin, Litecoin
}
