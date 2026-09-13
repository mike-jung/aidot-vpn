package com.aidotvpn.client.sampleapp

import okhttp3.HttpUrl.Companion.toHttpUrlOrNull

/** Validate before persisting an address or constructing the VPN engine. */
internal fun serverAddress(raw: String, requireHttps: Boolean = false): String {
    val url = raw.trim().toHttpUrlOrNull()
        ?: throw IllegalArgumentException("http:// 또는 https://로 시작하는 올바른 서버 주소를 입력하세요.")
    require(url.username.isEmpty() && url.password.isEmpty() && url.query == null && url.fragment == null) {
        "서버 주소에는 계정, 비밀번호, 쿼리 또는 #를 넣지 마세요."
    }
    require(!requireHttps || url.scheme == "https") { "배포용 앱에서는 https:// 서버 주소를 사용하세요." }
    return url.toString().trimEnd('/')
}
