package com.aidotvpn.client.core.relay

import android.util.Log
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * RelayClient bridges WireGuard's UDP socket to a remote relay server
 * over WebSocket-over-TLS (port 443).
 *
 * Architecture:
 *
 *     [wireguard-go inside the app]
 *         ↓ writes UDP packets to 127.0.0.1:wgLoopbackPort
 *     [LocalUdpSink (DatagramSocket on loopback)]
 *         ↓ thread reads each packet, frames it
 *     [WebSocket → wss://relay.example.com/ws/mobile]
 *         ↓ relay forwards ciphertext
 *     [wg-data-node bridge]
 *
 * Inbound direction is symmetric: WebSocket text frames are unwrapped and
 * sent back to the wireguard-go socket as UDP datagrams.
 *
 * This class does NOT decrypt or interpret WireGuard traffic. It moves
 * ciphertext only. Compromise of the relay (or this class) does not
 * compromise the tunnel — keys live exclusively in wireguard-go.
 *
 * Usage from TunnelManager:
 *
 *     val relay = RelayClient(
 *         relayUrl = "wss://relay.example.com/ws/mobile",
 *         relayToken = registrationFlow.fetchRelayToken(deviceId),
 *         targetNodeId = chosenNode.id,
 *         wgLoopbackPort = 51820,
 *     )
 *     relay.start()
 *     // configure wireguard-go peer endpoint = "127.0.0.1:51820"
 *     // ... tunnel runs as if it were a direct UDP connection ...
 *     relay.stop()
 *
 * Phase 9b status: this class is FUNCTIONAL but TunnelManager doesn't
 * yet wire it in automatically based on endpoint.mode. Manual smoke
 * testing only. Auto-routing lands in 9c once wg-go's "config endpoint
 * to loopback" path is verified end-to-end.
 */
class RelayClient(
    private val relayUrl: String,
    private val relayToken: String,
    private val targetNodeId: String,
    private val wgLoopbackPort: Int = DEFAULT_WG_LOOPBACK_PORT,
) {
    /**
     * Frame protocol — must match server's internal/relay/conn.go
     * exactly:
     *
     *     +------+----------+--------+----------+------+
     *     | 1B   | 2B (BE)  |  N B   | 2B (BE)  | M B  |
     *     +------+----------+--------+----------+------+
     *     | type | hdr_len  | header | data_len | data |
     *     +------+----------+--------+----------+------+
     */
    private object FrameType {
        const val HELLO: Byte = 1
        const val DATA: Byte = 2
        const val ERROR: Byte = 3
        const val PING: Byte = 4
    }

    private val state = AtomicReference(State.IDLE)
    private val wsRef = AtomicReference<WebSocket?>(null)
    private val sinkRef = AtomicReference<DatagramSocket?>(null)
    private var udpReadThread: Thread? = null
    private var pingThread: Thread? = null

    enum class State { IDLE, CONNECTING, READY, FAILED, STOPPED }

    fun currentState(): State = state.get()

    /**
     * Starts the bridge. Returns true when the WebSocket has handshaken
     * and the relay has acknowledged our hello frame. Blocks for up to
     * [helloTimeoutSeconds] seconds.
     */
    @Throws(IllegalStateException::class)
    fun start(helloTimeoutSeconds: Long = 10): Boolean {
        if (!state.compareAndSet(State.IDLE, State.CONNECTING)) {
            throw IllegalStateException("RelayClient already started or stopped")
        }

        // Bind a DatagramSocket on a fixed loopback port. wireguard-go
        // is configured (by TunnelManager) to dial this port instead of
        // a remote host. The socket is bidirectional — we read packets
        // wg-go sends here, and we send packets back the same way.
        val sink = try {
            DatagramSocket(InetSocketAddress("127.0.0.1", wgLoopbackPort))
        } catch (e: Exception) {
            state.set(State.FAILED)
            Log.w(TAG, "could not bind UDP loopback :$wgLoopbackPort", e)
            return false
        }
        sinkRef.set(sink)

        val client = OkHttpClient.Builder()
            // The relay WebSocket carries our own VPN-bridging traffic.
            // It MUST escape the wg0 tunnel — otherwise we'd be sending
            // wg ciphertext through a wg tunnel through the same relay,
            // a routing loop the kernel rejects. See SocketProtector
            // for the full rationale.
            .socketFactory(com.aidotvpn.client.core.ProtectingSocketFactory())
            .pingInterval(20, TimeUnit.SECONDS)
            .readTimeout(0, TimeUnit.MILLISECONDS) // long-lived
            .build()

        val req = Request.Builder()
            .url(relayUrl)
            .header("Authorization", "Bearer $relayToken")
            .build()

        val helloAcked = java.util.concurrent.CountDownLatch(1)

        val ws = client.newWebSocket(req, object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                // Send hello frame announcing which node_id we want to talk to.
                // .toByteString() is required: buildFrame returns ByteArray and
                // WebSocket.send takes String or ByteString. The other three
                // send sites convert; this one did not, so the module never
                // compiled — the file was only ever type-checked with a stub
                // whose send() happened to accept ByteArray.
                webSocket.send(
                    buildFrame(
                        FrameType.HELLO,
                        ByteArray(0),
                        targetNodeId.toByteArray(),
                    ).toByteString(),
                )
            }

            override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                handleInboundFrame(bytes.toByteArray(), helloAcked)
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                // We only speak binary frames; ignore text.
            }

            override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                Log.w(TAG, "ws failure: ${t.message}", t)
                state.set(State.FAILED)
                helloAcked.countDown() // unblock start()
            }

            override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                Log.i(TAG, "ws closed: $code $reason")
                state.set(State.STOPPED)
            }
        })
        wsRef.set(ws)

        val acked = helloAcked.await(helloTimeoutSeconds, TimeUnit.SECONDS)
        if (!acked || state.get() == State.FAILED) {
            stop()
            return false
        }

        // Hello acknowledged → start the egress pump (wg-go → relay).
        startUdpReadThread(sink, ws)
        startPingThread(ws)
        return true
    }

    /** Stop the bridge, closing both the WS and the loopback socket. */
    fun stop() {
        state.set(State.STOPPED)
        wsRef.getAndSet(null)?.close(1000, "stop")
        sinkRef.getAndSet(null)?.close()
        udpReadThread?.interrupt()
        pingThread?.interrupt()
    }

    // ----- inbound (relay → wg-go) -------------------------------------

    private fun handleInboundFrame(msg: ByteArray, helloAcked: java.util.concurrent.CountDownLatch) {
        if (msg.size < 5) return
        val buf = ByteBuffer.wrap(msg).order(ByteOrder.BIG_ENDIAN)
        val type = buf.get()
        val hdrLen = buf.short.toInt() and 0xFFFF
        if (buf.remaining() < hdrLen + 2) return
        buf.position(buf.position() + hdrLen) // skip header (unused inbound)
        val dataLen = buf.short.toInt() and 0xFFFF
        if (buf.remaining() < dataLen) return
        val data = ByteArray(dataLen)
        buf.get(data)

        when (type) {
            FrameType.HELLO -> {
                state.set(State.READY)
                helloAcked.countDown()
                Log.i(TAG, "relay hello ack received")
            }
            FrameType.DATA -> forwardToWireGuard(data)
            FrameType.ERROR -> {
                Log.w(TAG, "relay error: ${String(data)}")
                state.set(State.FAILED)
                helloAcked.countDown()
            }
            FrameType.PING -> {
                // server pinged; we already responded by sending our own
                // pings. No action needed.
            }
        }
    }

    private fun forwardToWireGuard(packet: ByteArray) {
        val sink = sinkRef.get() ?: return
        try {
            // We send to a well-known local address that wg-go is
            // listening on (loopback + WG_LOOPBACK_REPLY_PORT). wg-go's
            // socket source addr will be the same it sent FROM, which
            // matches.
            val datagram = DatagramPacket(
                packet, packet.size,
                InetAddress.getByName("127.0.0.1"),
                wgLoopbackPort + 1,
            )
            sink.send(datagram)
        } catch (e: Exception) {
            Log.w(TAG, "forward to wg failed", e)
        }
    }

    // ----- outbound (wg-go → relay) ------------------------------------

    private fun startUdpReadThread(sink: DatagramSocket, ws: WebSocket) {
        udpReadThread = thread(name = "aidotvpn-relay-udp", isDaemon = true) {
            val buf = ByteArray(64 * 1024)
            while (state.get() == State.READY) {
                try {
                    val pkt = DatagramPacket(buf, buf.size)
                    sink.receive(pkt)
                    val frame = buildFrame(FrameType.DATA, ByteArray(0),
                        pkt.data.copyOfRange(0, pkt.length))
                    ws.send(frame.toByteString())
                } catch (e: Exception) {
                    if (state.get() == State.READY) {
                        Log.w(TAG, "udp read failed", e)
                    }
                    break
                }
            }
        }
    }

    private fun startPingThread(ws: WebSocket) {
        pingThread = thread(name = "aidotvpn-relay-ping", isDaemon = true) {
            while (state.get() == State.READY) {
                try {
                    Thread.sleep(25_000)
                    ws.send(buildFrame(FrameType.PING, ByteArray(0), ByteArray(0)).toByteString())
                } catch (_: InterruptedException) {
                    return@thread
                } catch (_: Exception) {
                    return@thread
                }
            }
        }
    }

    private fun buildFrame(type: Byte, header: ByteArray, data: ByteArray): ByteArray {
        require(header.size <= 0xFFFF)
        require(data.size <= 0xFFFF)
        val buf = ByteBuffer.allocate(5 + header.size + data.size).order(ByteOrder.BIG_ENDIAN)
        buf.put(type)
        buf.putShort(header.size.toShort())
        buf.put(header)
        buf.putShort(data.size.toShort())
        buf.put(data)
        return buf.array()
    }

    private fun ByteArray.toByteString(): ByteString = this.toByteString(0, size)

    companion object {
        private const val TAG = "AidotVpn/Relay"
        const val DEFAULT_WG_LOOPBACK_PORT = 51820
    }
}
