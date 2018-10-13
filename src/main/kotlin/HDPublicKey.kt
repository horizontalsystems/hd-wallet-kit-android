class HDPublicKey() {

    var index = 0
    var external = true

    var publicKey: ByteArray = byteArrayOf()
    var publicKeyHash: ByteArray = byteArrayOf()


    constructor(index: Int, external: Boolean, key: HDKey) : this() {
        this.index = index
        this.external = external
        this.publicKey = key.pubKey
        this.publicKeyHash = key.pubKeyHash
    }

}
