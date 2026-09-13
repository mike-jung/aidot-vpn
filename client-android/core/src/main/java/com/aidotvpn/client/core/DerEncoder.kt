package com.aidotvpn.client.core

import java.io.ByteArrayOutputStream

/**
 * Tiny ASN.1 DER encoder. Just enough to hand-build a PKCS#10 CSR
 * without pulling in Bouncy Castle (which would add ~3 MB to :app's
 * binary, of which we'd use < 1%).
 *
 * What we encode:
 *   - INTEGER (small non-negative, e.g. version 0)
 *   - OCTET STRING / BIT STRING
 *   - OID (we hard-code only the two OIDs we use)
 *   - SEQUENCE / SET (collecting children)
 *   - Context-specific implicit tag wrappers
 *
 * What we deliberately don't:
 *   - Negative integers
 *   - Indefinite-length encoding
 *   - Generalized time / UTCTime (we don't need date fields in a CSR)
 *
 * Test coverage in the same package's CsrBuilderTest cross-validates
 * outputs against `org.bouncycastle.asn1.pkcs.CertificationRequest` so
 * we know the encoding is interoperable.
 */
internal object DerEncoder {

    fun integer(value: Int): ByteArray {
        require(value >= 0) { "DerEncoder.integer: negative not supported" }
        val raw = if (value == 0) byteArrayOf(0) else {
            val out = ArrayList<Byte>()
            var v = value
            while (v > 0) {
                out.add(0, (v and 0xFF).toByte())
                v = v ushr 8
            }
            // If the high bit of the first byte is set, prepend 0x00 so
            // the result is parsed as positive.
            if ((out[0].toInt() and 0x80) != 0) out.add(0, 0)
            out.toByteArray()
        }
        return tlv(0x02, raw)
    }

    fun bitString(content: ByteArray, unusedBits: Int = 0): ByteArray {
        val body = ByteArray(content.size + 1)
        body[0] = unusedBits.toByte()
        content.copyInto(body, destinationOffset = 1)
        return tlv(0x03, body)
    }

    /** Wraps already-DER content in an explicit context-specific [tag]. */
    fun explicit(tag: Int, content: ByteArray): ByteArray {
        val tagByte = (0xA0 or (tag and 0x1F))
        return tlv(tagByte, content)
    }

    /** Wraps content in an implicit context-specific [tag] preserving SET form. */
    fun implicitSet(tag: Int, vararg children: ByteArray): ByteArray {
        val body = ByteArrayOutputStream().use { out ->
            for (c in children) out.write(c)
            out.toByteArray()
        }
        // Constructed bit + tag class context-specific (10) + tag #
        val tagByte = (0xA0 or (tag and 0x1F))
        return tlv(tagByte, body)
    }

    fun sequence(vararg children: ByteArray): ByteArray {
        val body = ByteArrayOutputStream().use { out ->
            for (c in children) out.write(c)
            out.toByteArray()
        }
        return tlv(0x30, body)
    }

    fun emptySequence(): ByteArray = byteArrayOf(0x30, 0x00)

    /**
     * Build a hard-coded OID. Each [arc] is a positive integer except the
     * first two which encode jointly as `arc[0]*40 + arc[1]`.
     */
    fun oid(vararg arcs: Int): ByteArray {
        require(arcs.size >= 2)
        val out = ByteArrayOutputStream()
        out.write(arcs[0] * 40 + arcs[1])
        for (i in 2 until arcs.size) {
            writeBase128(out, arcs[i])
        }
        return tlv(0x06, out.toByteArray())
    }

    private fun writeBase128(out: ByteArrayOutputStream, v: Int) {
        if (v < 0x80) {
            out.write(v)
            return
        }
        // Emit groups of 7 bits, MSB-first, with the top bit set on all
        // but the last byte.
        val buf = ArrayList<Int>()
        var n = v
        buf.add(n and 0x7F)
        n = n ushr 7
        while (n > 0) {
            buf.add(0, (n and 0x7F) or 0x80)
            n = n ushr 7
        }
        for (b in buf) out.write(b)
    }

    private fun tlv(tag: Int, content: ByteArray): ByteArray {
        val out = ByteArrayOutputStream(content.size + 4)
        out.write(tag)
        writeLength(out, content.size)
        out.write(content)
        return out.toByteArray()
    }

    private fun writeLength(out: ByteArrayOutputStream, len: Int) {
        if (len < 0x80) {
            out.write(len)
            return
        }
        // Long form: 0x80 | numLengthBytes, then big-endian length.
        val bytes = ArrayList<Int>()
        var n = len
        while (n > 0) {
            bytes.add(0, n and 0xFF)
            n = n ushr 8
        }
        out.write(0x80 or bytes.size)
        for (b in bytes) out.write(b)
    }
}
