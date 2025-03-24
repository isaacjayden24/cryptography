import kotlin.random.Random

class StreamCipherAnalysis {
    class LFSR(private var state: Int, private val tapPositions: List<Int>) {
        fun nextBit(): Int {
            val output = state and 1
            val feedback = tapPositions.map { (state shr it) and 1 }.reduce { acc, bit -> acc xor bit }
            state = (state shr 1) or (feedback shl 15)
            return output
        }

        fun generateSequence(length: Int): List<Int> {
            return List(length) { nextBit() }
        }
    }

    fun encrypt(data: ByteArray, key: Int): ByteArray {
        val lfsr = LFSR(key, listOf(0, 2, 3, 5))
        val keystream = lfsr.generateSequence(data.size * 8)
        return data.mapIndexed { index, byte ->
            val keyByte = keystream.slice(index * 8 until (index + 1) * 8)
                .fold(0) { acc, bit -> (acc shl 1) or bit }
            (byte.toInt() xor keyByte).toByte()
        }.toByteArray()
    }

    fun decrypt(data: ByteArray, key: Int): ByteArray {
        return encrypt(data, key) // Symmetric encryption
    }
}

fun hexStringToByteArray(hex: String): ByteArray {
    return hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}

fun main() {
    val analyzer = StreamCipherAnalysis()
    val key = 42

    val hexCiphertexts = listOf(
        "6a657c5f1a3e4b584d",
        "6a657c5f1a3e4b584d"
    )

    for ((index, hexCipher) in hexCiphertexts.withIndex()) {
        val cipherBytes = hexStringToByteArray(hexCipher)
        val decryptedBytes = analyzer.decrypt(cipherBytes, key)
        val decryptedText = decryptedBytes.toString(Charsets.UTF_8)
        println("Decrypted Text $index: $decryptedText")
    }
}