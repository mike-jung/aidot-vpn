package com.aidotvpn.client.core

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import javax.net.SocketFactory

/**
 * Creates control-channel sockets outside our VPN before connecting them.
 *
 * Android allocates a plain Socket's native descriptor lazily. Binding an
 * unconnected socket to a wildcard/ephemeral local address creates that
 * descriptor; protecting a bare Socket() instead passes an invalid descriptor
 * to VpnService and fails. The order is bind, protect, then connect.
 *
 * Only SDK control clients use this factory. Business traffic keeps its normal
 * socket factory and remains subject to the VPN's app and destination policy.
 * A rejected protection request while our service is active fails immediately;
 * it must not silently send control traffic into the tunnel it manages.
 */
class ProtectingSocketFactory(
    private val delegate: SocketFactory = getDefault(),
) : SocketFactory() {
    private fun newProtectedSocket(local: InetSocketAddress? = null): Socket {
        val socket = delegate.createSocket()
        try {
            socket.bind(local ?: InetSocketAddress(0))
            if (SocketProtector.isActive && !SocketProtector.protect(socket)) {
                throw IOException("VPN control socket protection failed")
            }
            return socket
        } catch (error: Exception) {
            runCatching { socket.close() }
            throw error
        }
    }

    private fun connected(remote: InetSocketAddress, local: InetSocketAddress? = null): Socket {
        val socket = newProtectedSocket(local)
        try {
            socket.connect(remote)
            return socket
        } catch (error: Exception) {
            runCatching { socket.close() }
            throw error
        }
    }

    override fun createSocket(): Socket = newProtectedSocket()
    override fun createSocket(host: String?, port: Int): Socket =
        connected(InetSocketAddress(host, port))
    override fun createSocket(host: String?, port: Int, localHost: InetAddress?, localPort: Int): Socket =
        connected(InetSocketAddress(host, port), InetSocketAddress(localHost, localPort))
    override fun createSocket(host: InetAddress?, port: Int): Socket =
        connected(InetSocketAddress(host, port))
    override fun createSocket(address: InetAddress?, port: Int, localAddress: InetAddress?, localPort: Int): Socket =
        connected(InetSocketAddress(address, port), InetSocketAddress(localAddress, localPort))
}
