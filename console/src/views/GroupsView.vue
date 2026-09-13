<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
/**
 * 그룹 — a policy applied to many devices at once.
 *
 * A policy used to be attached one device at a time, so changing what a
 * ward can reach meant an edit per phone and a missed one stayed on the
 * old rules silently. Here the policy sits on the group; the device
 * list still names the policy in force and where it came from, because
 * "why can this phone reach that" must stay answerable from the device.
 */
import { ref, onMounted } from 'vue'
import { groups as groupsAPI, policies as policiesAPI, APIError } from '@/api/client.js'
import AidotDialog from '../components/AidotDialog.vue'

const list = ref([])
const policyList = ref([])
const loading = ref(true)
const err = ref('')

const newName = ref('')
const newDesc = ref('')
const newPolicy = ref('')
const creating = ref(false)

const removing = ref(null)
const saving = ref(new Set())
const saved = ref('')

async function load () {
  loading.value = true
  err.value = ''
  try {
    const [g, p] = await Promise.all([groupsAPI.list(), policiesAPI.list()])
    // policy_id must exist on every row for v-model to bind; the API
    // omits it when a group has no policy.
    list.value = (g.groups || []).map((x) => ({ ...x, policy_id: x.policy_id || '', savedPolicyId: x.policy_id || '' }))
    policyList.value = p.policies || []
  } catch (e) {
    err.value = e instanceof APIError ? e.message : String(e)
  } finally {
    loading.value = false
  }
}

async function create () {
  if (!newName.value.trim()) return
  creating.value = true
  try {
    await groupsAPI.create(newName.value.trim(), newDesc.value.trim(), newPolicy.value)
    newName.value = ''
    newDesc.value = ''
    newPolicy.value = ''
    await load()
  } catch (e) {
    err.value = e?.message || String(e)
  } finally {
    creating.value = false
  }
}

/** One write, every member. */
async function setPolicy (g, policyId) {
  if (saving.value.has(g.id)) return
  saving.value.add(g.id)
  err.value = ''
  saved.value = ''
  try {
    await groupsAPI.setPolicy(g.id, policyId)
    g.savedPolicyId = policyId
    saved.value = `${g.name} 정책을 저장했습니다. 게이트웨이 동기화 후 적용되며 단말 설정은 다시 연결해 갱신하세요.`
  } catch (e) {
    g.policy_id = g.savedPolicyId
    err.value = e?.message || String(e)
  } finally {
    saving.value.delete(g.id)
  }
}

async function confirmRemove () {
  const g = removing.value
  removing.value = null
  if (!g) return
  try {
    await groupsAPI.remove(g.id)
    await load()
  } catch (e) {
    err.value = e?.message || String(e)
  }
}

onMounted(load)
</script>

<template>
  <div class="container-fluid py-3">
    <h1 class="h4 mb-1"> {{ tr("그룹") }} </h1>
    <p class="text-muted small mb-3"> {{ tr("정책을 그룹에 붙이면 그 그룹의 단말 전부에 한 번에 적용됩니다. 단말에 정책을 따로 지정하면 그쪽이 우선합니다.") }} </p>

    <div v-if="saved" role="status" class="alert alert-success py-2 small">{{ tr(saved) }}</div>
    <div v-if="err" role="alert" class="alert alert-danger py-2 small">{{ tr(err) }}</div>

    <div class="row g-3">
      <div class="col-md-4">
        <div class="card">
          <div class="card-header py-2"><strong> {{ tr("새 그룹 만들기") }} </strong></div>
          <div class="card-body">
            <input v-model="newName" class="form-control form-control-sm mb-2"
                   :placeholder="tr(&quot;그룹 이름 (예: 3층 간호사)&quot;)" />
            <input v-model="newDesc" class="form-control form-control-sm mb-2"
                   :placeholder="tr(&quot;설명 (선택)&quot;)" />
            <select v-model="newPolicy" class="form-select form-select-sm mb-2">
              <option value=""> {{ tr("정책 나중에 정하기") }} </option>
              <option v-for="p in policyList" :key="p.id" :value="p.id">{{ p.name }}</option>
            </select>
            <button class="btn btn-primary btn-sm w-100"
                    :disabled="creating || !newName.trim()" @click="create"> {{ tr("만들기") }} </button>
          </div>
        </div>
      </div>

      <div class="col-md-8">
        <div class="card">
          <div class="card-header py-2"><strong> {{ tr("그룹 목록") }} </strong></div>
          <div class="card-body p-0">
            <div v-if="loading" class="text-muted small p-3"> {{ tr("불러오는 중…") }} </div>
            <div v-else-if="!list.length" class="text-muted small p-3"> {{ tr("아직 그룹이 없습니다. 왼쪽에서 만들 수 있습니다.") }} </div>
            <table v-else class="table table-sm align-middle mb-0">
              <thead>
                <tr>
                  <th> {{ tr("이름") }} </th>
                  <th style="width: 12rem"> {{ tr("정책") }} </th>
                  <th style="width: 6rem" class="text-end"> {{ tr("단말") }} </th>
                  <th style="width: 5rem" class="text-end"> {{ tr("삭제") }} </th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="g in list" :key="g.id">
                  <td>
                    <div class="fw-semibold">{{ g.name }}</div>
                    <div v-if="g.description" class="text-muted small">{{ g.description }}</div>
                  </td>
                  <td>
                    <!--
                      v-model on the row's own field, with a watcher
                      doing the write: the template stays free of
                      expressions, which is what check-vue asks for and
                      what keeps the logic testable.
                    -->
                    <select
                      v-model="g.policy_id"
                      :disabled="saving.has(g.id)"
                      :aria-label="tr(`${g.name} 적용 정책`)"
                      class="form-select form-select-sm"
                      @change="setPolicy(g, g.policy_id)"
                    >
                      <option value=""> {{ tr("(없음)") }} </option>
                      <option v-for="p in policyList" :key="p.id" :value="p.id">{{ p.name }}</option>
                    </select>
                  </td>
                  <td class="text-end">
                    <span :class="g.members ? '' : 'text-muted'"> {{ tr("{0}대", [g.members]) }} </span>
                  </td>
                  <td class="text-end">
                    <button class="btn btn-sm btn-outline-danger" type="button"
                            @click="removing = g"> {{ tr("삭제") }} </button>
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <AidotDialog
      :open="!!removing" :title="tr(&quot;그룹 삭제&quot;)" tone="danger" :confirm-label="tr(&quot;삭제&quot;)"
      :cancel-label="tr(&quot;취소&quot;)"
      @update:open="(v) => { if (!v) removing = null }"
      @confirm="confirmRemove"
    >
      <p v-if="removing" class="mb-0">
        <strong>{{ removing.name }}</strong> {{ tr("을(를) 삭제합니다. 속한 단말 {0}대는 그룹 정책을 잃습니다. 단말에 개별 정책이 없으면 연결이 거부됩니다. 개별 지정 정책은 유지됩니다.", [removing.members]) }} </p>
    </AidotDialog>
  </div>
</template>
