<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
/**
 * Who can reach where, drawn rather than tabulated.
 *
 * Not the topology other consoles show. NetBird and Tailscale draw peers
 * connected to peers because they are meshes and A-B is a real line.
 * Everything here passes through the gateway, so that picture is one
 * star and says nothing.
 *
 * The questions an admin has are about reach, and each needed several
 * screens and a comparison done in the head:
 *
 *   이 정책이 여는 대역이 어디인가       정책 화면에서 목록을 읽음
 *   두 정책이 겹치나                    두 화면을 열어 눈으로 비교
 *   아무도 안 쓰는 대역이 있나           알 방법 없음
 *
 * Three columns — 단말 · 정책 · 대역 — answer all of them at once.
 */
import { ref, onMounted, computed } from 'vue'
import { reach as reachAPI } from '@/api/client.js'

const loading = ref(true)
const edges = ref([])
const overlaps = ref({})
const unbound = ref(0)
const error = ref('')

/** Policies, each with its CIDRs and how many devices are bound. */
const policies = computed(() => {
  const m = new Map()
  for (const e of edges.value) {
    if (!m.has(e.policy_id)) {
      m.set(e.policy_id, { id: e.policy_id, name: e.policy, devices: e.device_count, cidrs: [] })
    }
    m.get(e.policy_id).cidrs.push(e)
  }
  return [...m.values()]
})

/**
 * A CIDR nothing can reach.
 *
 * Opened by a policy that no active device is bound to — so the line
 * exists in the config and carries nothing. Worth surfacing because it
 * is invisible in every other view: the policy screen shows the CIDR,
 * the device screen shows the policy, and neither joins them.
 */
const orphans = computed(() =>
  edges.value.filter((e) => e.device_count === 0))

const overlapCount = computed(() => Object.keys(overlaps.value).length)

function isOverlapping (cidr) {
  return Object.prototype.hasOwnProperty.call(overlaps.value, cidr)
}

async function load () {
  loading.value = true
  error.value = ''
  try {
    const d = await reachAPI.get()
    edges.value = d.edges || []
    overlaps.value = d.overlaps || {}
    unbound.value = d.unbound || 0
  } catch (e) {
    error.value = String(e)
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div>
        <h1 class="h4 mb-0"> {{ tr("도달 범위") }} </h1>
        <div class="text-muted small"> {{ tr("어느 단말이 어느 정책을 거쳐 어디까지 갈 수 있는지") }} </div>
      </div>
      <button class="btn btn-sm btn-outline-secondary" type="button" @click="load"> {{ tr("새로고침") }} </button>
    </div>

    <div v-if="error" class="alert alert-danger py-2 small">{{ tr(error) }}</div>
    <div v-else-if="loading" class="text-muted p-4"> {{ tr("불러오는 중…") }} </div>

    <template v-else>
      <div v-if="overlapCount || orphans.length || unbound" class="row g-2 mb-3">
        <div v-if="unbound" class="col-auto">
          <span class="badge bg-danger-subtle text-danger-emphasis p-2"> {{ tr("정책 없는 단말 {0}대 — 연결이 거부됩니다", [unbound]) }} </span>
        </div>
        <div v-if="overlapCount" class="col-auto">
          <span class="badge bg-warning-subtle text-warning-emphasis p-2"> {{ tr("겹치는 대역 {0}개 — 두 정책이 같은 곳을 엽니다", [overlapCount]) }} </span>
        </div>
        <div v-if="orphans.length" class="col-auto">
          <span class="badge bg-secondary-subtle text-secondary-emphasis p-2"> {{ tr("쓰이지 않는 대역 {0}개 — 붙은 단말이 없습니다", [orphans.length]) }} </span>
        </div>
      </div>

      <div v-if="!policies.length" class="card">
        <div class="card-body text-center text-muted py-5">
          <div class="fw-bold mb-1"> {{ tr("아직 정책이 없습니다.") }} </div>
          <div class="small"> {{ tr("정책을 만들고 대역을 추가하면 여기에 그려집니다.") }} </div>
        </div>
      </div>

      <div v-else class="reach">
        <div class="reach-head">
          <div> {{ tr("단말") }} </div>
          <div> {{ tr("정책") }} </div>
          <div> {{ tr("갈 수 있는 곳") }} </div>
        </div>

        <div v-for="p in policies" :key="p.id" class="reach-row">
          <div class="reach-col">
            <div class="chip" :class="p.devices ? 'chip-live' : 'chip-empty'">
               {{ tr("{0}대", [p.devices]) }} </div>
          </div>

          <div class="reach-col reach-mid">
            <div class="link-line" />
            <div class="chip chip-policy">{{ p.name }}</div>
            <div class="link-line" />
          </div>

          <div class="reach-col reach-dests">
            <div
              v-for="c in p.cidrs" :key="c.cidr"
              class="chip chip-cidr"
              :class="{
                'chip-overlap': isOverlapping(c.cidr),
                'chip-orphan': c.device_count === 0,
              }"
            >
              <code>{{ c.cidr }}</code>
              <span v-if="c.description" class="d-block text-muted" style="font-size:.7rem">
                {{ c.description }}
              </span>
              <span
                v-if="isOverlapping(c.cidr)"
                class="d-block" style="font-size:.68rem"
              > {{ tr("{0} 가 함께 엽니다", [overlaps[c.cidr].join(' · ')]) }} </span>
            </div>
            <div v-if="!p.cidrs.length" class="text-muted small"> {{ tr("대역 없음") }} </div>
          </div>
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.page-head { display: flex; align-items: flex-start; justify-content: space-between; margin-bottom: 1rem; }
.reach { background: var(--panel); border: 1px solid var(--line); border-radius: .5rem; overflow: hidden; }
.reach-head {
  display: grid; grid-template-columns: 6rem 12rem 1fr;
  gap: .5rem; padding: .5rem .75rem;
  background: var(--panel-2); border-bottom: 1px solid var(--line);
  font-size: .8rem; font-weight: 600; color: var(--text);
}
.reach-row {
  display: grid; grid-template-columns: 6rem 12rem 1fr;
  gap: .5rem; padding: .75rem; align-items: center;
  border-bottom: 1px solid var(--line);
}
.reach-row:last-child { border-bottom: 0; }
.reach-mid { display: flex; align-items: center; gap: .25rem; }
.link-line { flex: 1; height: 2px; background: var(--line-2); }
.reach-dests { display: flex; flex-wrap: wrap; gap: .4rem; }
.chip {
  display: inline-block; padding: .3rem .55rem;
  border-radius: .35rem; font-size: .8rem; border: 1px solid transparent;
}
.chip-live { background: var(--good-soft); color: var(--good); border-color: rgba(34,197,94,.35); font-weight: 600; }
.chip-empty { background: var(--panel-2); color: var(--text-3); }
.chip-policy { background: var(--text); color: var(--panel); font-weight: 600; white-space: nowrap; }
.chip-cidr { background: var(--panel-2); border-color: var(--line); }
/* Overlap and orphan are different problems, so they read differently. */
.chip-overlap { background: var(--warn-soft); border-color: rgba(245,179,1,.4); color: var(--warn); }
.chip-orphan { opacity: .6; border-style: dashed; }
</style>
