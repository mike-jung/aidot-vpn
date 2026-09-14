const recoveryKey = 'aidotvpn.login.navigation-recovery'
const recoveryWindowMs = 60_000
const navigationMessage = '로그인 후 화면을 열지 못했습니다. 다시 시도하세요.'

function isLocalPath(value) {
  return typeof value === 'string' && value.startsWith('/') &&
    !value.startsWith('//') && !/[\\\u0000-\u0020]/.test(value)
}

export function loginDestination(router, next, mustChangePassword) {
  if (mustChangePassword) return { name: 'overview', query: { changePassword: '1' } }
  if (!isLocalPath(next)) return { name: 'overview' }
  const route = router.resolve(next)
  return route.name !== 'login' && route.meta.requiresAuth ? route.fullPath : { name: 'overview' }
}

// A tab opened before a deployment can refer to a removed JS/CSS chunk.
// Retry from the current HTML once; retain the cookie and the intended route.
export function recoverLoginAssets(error, target, browser = globalThis.window) {
  if (!isLocalPath(target) || !browser) return false
  if (!/Failed to fetch dynamically imported module|Importing a module script failed|error loading dynamically imported module|Unable to preload CSS|Loading (?:CSS )?chunk .+ failed/i.test(error?.message || '')) return false
  try {
    const previous = JSON.parse(browser.sessionStorage.getItem(recoveryKey) || 'null')
    const now = Date.now()
    if (previous && now - previous.at < recoveryWindowMs) return false
    browser.sessionStorage.setItem(recoveryKey, JSON.stringify({ at: now }))
    browser.location.replace(target)
    return true
  } catch {
    // Without a persistent marker, a reload could repeat indefinitely.
    return false
  }
}

export async function navigateAfterLogin(router, target, browser = globalThis.window) {
  try {
    const failure = await router.replace(target)
    if (failure && router.currentRoute.value.name === 'login') throw failure
  } catch (error) {
    if (recoverLoginAssets(error, router.resolve(target).fullPath, browser)) return
    throw new Error(navigationMessage, { cause: error })
  }
}
