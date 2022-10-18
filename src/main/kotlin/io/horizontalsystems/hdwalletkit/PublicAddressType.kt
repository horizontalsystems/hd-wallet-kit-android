package io.horizontalsystems.hdwalletkit

enum class PublicAddressType(
    val publicMagicBytes: Int,
    val privateMagicBytes: Int
) {

    // -- Bitcoin Regin Begin
    /* Main Net Pub Address Bytes */
    P2PKH(0x0488b21e, 0x0488ade4), // xpub, xprv
    P2WPKH_P2SH(0x049d7cb2, 0x049d7878), // ypub, ypriv
    P2WSH_P2SH(0x0295b43f, 0x0295b005), // Ypub, Ypriv
    P2WPKH(0x04b24746, 0x04b2430c), // zpub, zpriv
    P2WSH(0x02aa7ed3, 0x02aa7a99), // Zpub. Zpriv
    /* ========================= */

    /* Test Net Pub Address Bytes */
    TEST_P2PKH(0x043587cf, 0x04358394), // tpub, tpriv
    TEST_P2WPKH_P2SH(0x044a5262, 0x044a4e28), // upub, upriv
    TEST_P2WSH_P2SH(0x024289ef, 0x024285b5), // Upub, Upriv
    TEST_P2WPKH(0x045f1cf6, 0x045f18bc), // vpub, vpriv
    TEST_P2WSH(0x02575483, 0x02575048); // Vpub, Vpriv
    /* ========================= */
    // -- Bitcoin Regin End
}