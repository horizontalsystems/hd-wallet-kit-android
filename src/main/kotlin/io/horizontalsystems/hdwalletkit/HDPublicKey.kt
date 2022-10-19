package io.horizontalsystems.hdwalletkit

class HDPublicKey() {
    var publicKey: ByteArray = byteArrayOf()
    var publicKeyHash: ByteArray = byteArrayOf()

    constructor(key: HDKey) : this() {
        this.publicKey = key.pubKey
        this.publicKeyHash = key.pubKeyHash
    }

}
