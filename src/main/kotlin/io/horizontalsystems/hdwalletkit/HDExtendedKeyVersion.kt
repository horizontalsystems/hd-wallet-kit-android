package io.horizontalsystems.hdwalletkit

import io.horizontalsystems.hdwalletkit.HDWallet.Purpose
import java.lang.IllegalStateException
import java.math.BigInteger

enum class HDExtendedKeyVersion(
    val value: Int,
    val base58Prefix: String
) {

    // bip44
    xprv(0x0488ade4, "xprv"),
    xpub(0x0488b21e, "xpub"),

    // bip49
    yprv(0x049d7878, "yprv"),
    ypub(0x049d7cb2, "ypub"),

    // bip84
    zprv(0x04b2430c, "zprv"),
    zpub(0x04b24746, "zpub"),

    // litecoin bip44
    Ltpv(0x019d9cfe, "Ltpv"),
    Ltub(0x019da462, "Ltub"),

    // litecoin bip49
    Mtpv(0x01b26792, "Mtpv"),
    Mtub(0x01b26ef6, "Mtub");

    val coinTypes: List<ExtendedKeyCoinType>
        get() = when (this) {
            xprv, xpub, zprv, zpub -> {
                listOf(ExtendedKeyCoinType.Bitcoin, ExtendedKeyCoinType.Litecoin)
            }

            yprv, ypub -> {
                listOf(ExtendedKeyCoinType.Bitcoin)
            }

            Ltpv, Ltub, Mtpv, Mtub -> {
                listOf(ExtendedKeyCoinType.Litecoin)
            }
        }

    val purposes: List<Purpose>
        get() = when (this) {
            xprv, xpub -> {
                listOf(Purpose.BIP44, Purpose.BIP86)
            }

            Ltpv, Ltub -> {
                listOf(Purpose.BIP44)
            }

            yprv, ypub, Mtpv, Mtub -> {
                listOf(Purpose.BIP49)
            }

            zprv, zpub -> {
                listOf(Purpose.BIP84)
            }
        }

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

    val isPublic: Boolean
        get() = when (this) {
            xprv, yprv, zprv, Ltpv, Mtpv -> false
            xpub, ypub, zpub, Ltub, Mtub -> true
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

                Purpose.BIP86 -> {
                    if (isPrivate) xprv else xpub
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
