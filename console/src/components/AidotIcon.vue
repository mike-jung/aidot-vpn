<script setup>
import { translate as tr, localeTag } from '../i18n/index.js'
/**
 * AidotIcon — the console's icon set, drawn here rather than imported.
 *
 * ## Why hand-drawn rather than a library
 *
 * The console previously used Unicode dingbats (📱 🗄 🛡 📜 ⚙). Those
 * render as the OS emoji font, so the sidebar looked different on
 * Windows, macOS and Linux, sat at a different optical weight than the
 * text beside them, and could not take the hover colour — an emoji
 * ignores `currentColor` entirely.
 *
 * Pulling in Lucide or Phosphor would fix that and add a dependency for
 * seven glyphs. Seven is under the threshold where a library pays for
 * itself, and this project has no other use for one.
 *
 * ## The grid these follow
 *
 * The 2026 convention across Lucide, Phosphor, Heroicons and Tabler is
 * the same, so it is what these use:
 *
 *   - 24×24 viewBox, artwork inside ~22×22 so nothing touches the edge
 *   - stroke, not fill: `fill="none"` with `stroke="currentColor"`
 *   - 1.75px stroke — between Lucide's 2 and Iconoir's 1.5, which suits
 *     a dense admin sidebar better than either
 *   - round caps and joins
 *   - corner radii from a small fixed set rather than drawn by eye
 *
 * `currentColor` is the part that matters most in practice: hover,
 * active and disabled states all work with no icon-specific CSS,
 * because the glyph inherits whatever colour its container has.
 *
 * ## Choosing what each icon depicts
 *
 * Each one had to be recognisable at 20px and distinct from its
 * neighbours in the same rail — the second constraint is the harder one.
 * A shield and a lock read as almost identical at that size, so 정책
 * (shield) and the password affordances elsewhere deliberately do not
 * both use shield-like outlines.
 */
defineProps({
  name: { type: String, required: true },
  size: { type: [Number, String], default: 20 },
  /** Stroke weight. 1.75 by default; 2 reads better under 18px. */
  stroke: { type: [Number, String], default: 1.75 },
})
</script>

<template>
  <svg
    :width="size"
    :height="size"
    viewBox="0 0 24 24"
    fill="none"
    stroke="currentColor"
    :stroke-width="stroke"
    stroke-linecap="round"
    stroke-linejoin="round"
    aria-hidden="true"
    focusable="false"
    class="aidot-icon"
  >
    <!-- 디바이스 — a handset. Rounded body, speaker slot, home indicator.
         The slot and indicator are what stop it reading as a plain
         rectangle at small sizes. -->
    <template v-if="name === 'devices'">
      <rect x="6" y="2.5" width="12" height="19" rx="2.5" />
      <path d="M10.5 5.5h3" />
      <path d="M10.75 18.5h2.5" />
    </template>

    <!-- 노드 — stacked server units. Three tiers with a status dot each;
         the dots are what distinguish it from a generic "layers" glyph. -->
    <template v-else-if="name === 'nodes'">
      <rect x="3" y="3" width="18" height="5.5" rx="1.5" />
      <rect x="3" y="15.5" width="18" height="5.5" rx="1.5" />
      <path d="M6.5 5.75h.01M6.5 18.25h.01" />
      <path d="M3 12h18" stroke-dasharray="0.01 4" />
    </template>

    <!-- 정책 — a shield with a check. The check says "allowed", which is
         what a policy grants; a plain shield would read as generic
         security. -->
    <template v-else-if="name === 'policies'">
      <path d="M12 2.5 4.5 5.5v6c0 4.5 3 8.3 7.5 10 4.5-1.7 7.5-5.5 7.5-10v-6L12 2.5Z" />
      <path d="m9 11.75 2.25 2.25L15.25 10" />
    </template>

    <!-- 감사 로그 — a document with ruled lines and a folded corner.
         The fold is the cheapest way to say "record" rather than
         "window". -->
    <template v-else-if="name === 'audit'">
      <path d="M14 2.5H7a2 2 0 0 0-2 2v15a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V7.5L14 2.5Z" />
      <path d="M14 2.5v5h5" />
      <path d="M8.5 13h7M8.5 16.5h4.5" />
    </template>

    <!-- 설정 — sliders, not a cog.
         A cog at 20px turns into a blurred circle, and every third icon
         in every admin UI is a cog. Two tracks with offset handles stay
         legible and say "adjust" more directly. -->
    <template v-else-if="name === 'settings'">
      <path d="M4 8h10M18 8h2" />
      <path d="M4 16h4M12 16h8" />
      <circle cx="16" cy="8" r="2.25" />
      <circle cx="10" cy="16" r="2.25" />
    </template>

    <!-- 줄이기 — collapse the rail. A panel edge with an arrow pointing
         into it. The vertical line is the wall the rail collapses to, so
         the direction is unambiguous without a label. -->
    <template v-else-if="name === 'collapse'">
      <path d="M4 4v16" />
      <path d="M20 12H9" />
      <path d="m13 8-4 4 4 4" />
    </template>

    <!-- 원래대로 — the mirror image. Same wall, arrow pointing away. -->
    <template v-else-if="name === 'expand'">
      <path d="M4 4v16" />
      <path d="M9 12h11" />
      <path d="m16 8 4 4-4 4" />
    </template>

    <!-- 프로필 — head and shoulders. -->
    <template v-else-if="name === 'profile'">
      <circle cx="12" cy="8" r="3.75" />
      <path d="M4.5 20.5a7.5 7.5 0 0 1 15 0" />
    </template>

    <!-- 로그아웃 — door with an arrow leaving it. -->
    <template v-else-if="name === 'logout'">
      <path d="M9.5 3.5H6a2 2 0 0 0-2 2v13a2 2 0 0 0 2 2h3.5" />
      <path d="M15 8.5 19 12l-4 3.5" />
      <path d="M19 12H9.5" />
    </template>

    <!-- 비밀번호 — a key. -->
    <template v-else-if="name === 'key'">
      <circle cx="7.5" cy="15.5" r="4" />
      <path d="m10.5 12.5 8-8" />
      <path d="m15.5 7.5 2 2M18 5l2 2" />
    </template>

    <!-- 닫기 -->
    <template v-else-if="name === 'close'">
      <path d="m6 6 12 12M18 6 6 18" />
    </template>

    <!-- 아래 화살표 (드롭다운 표시) -->
    <template v-else-if="name === 'chevron-down'">
      <path d="m6 9.5 6 6 6-6" />
    </template>

    <!-- 경고 — used where the ⚠ character used to be. -->
    <template v-else-if="name === 'alert'">
      <path d="M10.3 3.9 1.9 18a2 2 0 0 0 1.7 3h16.8a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0Z" />
      <path d="M12 9v4M12 17h.01" />
    </template>
  </svg>
</template>

<style scoped>
.aidot-icon {
  /* Sits on the text baseline rather than the line box, so an icon
     beside a label lines up with the label's centre instead of floating
     above it. */
  vertical-align: -0.15em;
  flex: 0 0 auto;
}
</style>
