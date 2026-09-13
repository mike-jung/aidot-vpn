<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
import { ref, onMounted } from 'vue'
import { consoleConnection } from '../api/client.js'
const form = ref(null), busy = ref(false), error = ref(''), nextURL = ref(''), managed = ref([])
onMounted(async () => {
  try { const v = await consoleConnection.get(); managed.value = v.managedByEnvironment; form.value = {bindHost:v.bindHost, port:v.port, publicURL:v.publicURL, https:{...v.https}} }
  catch (e) { error.value = e.message }
})
function scheme() {
  try { const u = new URL(form.value.publicURL); u.protocol = form.value.https.enabled ? 'https:' : 'http:'; u.port = String(form.value.port); form.value.publicURL = u.origin } catch {}
}
async function save() {
  busy.value = true; error.value = ''; nextURL.value = ''
  try { const result = await consoleConnection.save(form.value); nextURL.value = result.reconnectURL }
  catch (e) { error.value = e.message }
  finally { busy.value = false }
}
</script>
<template>
  <section class="card mb-4">
    <div class="card-header"><strong> {{ tr("콘솔 접속 · HTTPS") }} </strong></div>
    <div class="card-body">
      <p class="small text-muted"> {{ tr("인증서와 개인키는 서버에 PEM 파일로 저장하세요. 저장하면 접속 주소가 즉시 바뀝니다. 새 주소에서 다시 로그인하세요.") }} </p>
      <p v-if="error" role="alert" class="alert alert-danger small">{{ tr(error) }}</p>
      <p v-if="managed.length" class="alert alert-info small"> {{ tr("환경 변수로 관리 중입니다. console.env 또는 .env를 수정한 뒤 서버를 다시 시작하세요.") }} </p>
      <form v-if="form" @submit.prevent="save">
        <fieldset :disabled="busy || !!nextURL">
          <div class="form-check form-switch mb-3">
            <input id="console-https" :disabled="managed.includes('CONSOLE_HTTPS_ENABLED')" v-model="form.https.enabled" class="form-check-input" type="checkbox" @change="scheme" />
            <label for="console-https" class="form-check-label"> {{ tr("HTTPS 사용") }} </label>
          </div>
          <div class="row g-3">
            <div class="col-sm-8"><label for="console-bind" class="form-label"> {{ tr("수신 주소") }} </label><input id="console-bind" :disabled="managed.includes('CONSOLE_BIND_HOST')" v-model="form.bindHost" class="form-control" required /></div>
            <div class="col-sm-4"><label for="console-port" class="form-label"> {{ tr("포트") }} </label><input id="console-port" :disabled="managed.includes('CONSOLE_PORT')" v-model.number="form.port" class="form-control" type="number" min="1" max="65535" required @change="scheme" /></div>
            <div class="col-12"><label for="console-url" class="form-label"> {{ tr("브라우저 접속 주소") }} </label><input id="console-url" :disabled="managed.includes('CONSOLE_PUBLIC_URL')" v-model="form.publicURL" class="form-control" type="url" required /><div class="form-text"> {{ tr("인증서에 포함된 호스트 이름과 실제 수신 포트를 사용하세요.") }} </div></div>
            <template v-if="form.https.enabled">
              <div class="col-12"><label for="console-cert" class="form-label"> {{ tr("인증서 체인 파일의 절대 경로") }} </label><input id="console-cert" :disabled="managed.includes('CONSOLE_TLS_CERT_FILE')" v-model="form.https.certFile" class="form-control" required spellcheck="false" /></div>
              <div class="col-12"><label for="console-key" class="form-label"> {{ tr("개인키 파일의 절대 경로") }} </label><input id="console-key" :disabled="managed.includes('CONSOLE_TLS_KEY_FILE')" v-model="form.https.keyFile" class="form-control" required spellcheck="false" /></div>
            </template>
          </div>
          <p v-if="!form.https.enabled" class="text-warning small mt-3"> {{ tr("HTTP는 통신을 암호화하지 않습니다. 운영 환경에서는 HTTPS를 사용하세요.") }} </p>
          <button class="btn btn-primary mt-3" type="submit">{{ tr(busy ? '적용 중…' : '저장하고 적용') }}</button>
        </fieldset>
      </form>
      <div v-if="nextURL" role="status" class="alert alert-success mt-3 mb-0">
        <p> {{ tr("접속 설정을 적용했습니다. 브라우저가 신뢰하는 인증서가 필요합니다.") }} </p>
        <a :href="nextURL" class="btn btn-success"> {{ tr("새 주소로 콘솔 열기") }} </a>
      </div>
    </div>
  </section>
</template>
