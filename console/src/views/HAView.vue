<!-- SPDX-License-Identifier: Apache-2.0 -->
<script setup>
import { locale } from '../i18n/index.js'
const contact = 'mailto:mike.jung.global@gmail.com?subject=AidotVPN%20Enterprise%20inquiry'
</script>
<template>
  <section class="enterprise-page">
    <p class="edition">AidotVPN Enterprise</p>
    <h1>{{ locale === 'ko' ? '모바일 단말 관리의 서비스 연속성' : 'Service continuity for your mobile fleet' }}</h1>
    <p>{{ locale === 'ko' ? 'Public은 단일 서버에서 단말 등록, 접속 정책, VPN과 감사 로그를 제공합니다. 여러 서버의 장애 전환이 필요하면 Enterprise를 문의하세요.' : 'Public provides device enrollment, access policies, VPN connectivity and audit logs on a standalone server. Contact us for Enterprise deployment across redundant servers.' }}</p>
    <ul v-if="locale === 'ko'">
      <li>Active–Standby 고가용성 구성</li><li>복제 확인을 통한 등록·정책 변경 보호</li><li>펜싱과 제한 시간 기반 게이트웨이 보호</li><li>클러스터 서비스 시작·중지·상태 점검 자동화</li>
    </ul>
    <ul v-else>
      <li>Active–Standby high availability</li><li>Replication acknowledgement for enrollment and policy changes</li><li>Fencing integration and expiring gateway forwarding leases</li><li>Coordinated cluster service startup, shutdown and health checks</li>
    </ul>
    <a :href="contact">{{ locale === 'ko' ? 'Enterprise 문의' : 'Contact us about Enterprise' }}</a>
    <p class="contact">mike.jung.global@gmail.com</p>
  </section>
</template>
<style scoped>
.enterprise-page{max-width:850px;margin:0 auto;padding:32px;line-height:1.7}.edition{font-weight:700;color:#2563eb}h1{font-size:28px;line-height:1.3}ul{padding-left:24px;margin:24px 0}li{margin:10px 0}a{display:inline-block;background:#1d4ed8;color:white;padding:12px 20px;border-radius:9px;font-weight:600;text-decoration:none}a:focus-visible{outline:3px solid #60a5fa;outline-offset:4px}.contact{font-size:14px;opacity:.8}@media(max-width:600px){.enterprise-page{padding:20px}h1{font-size:23px}}
</style>
