// Vue Router config. Routes are intentionally enumerated rather than
// generated from filesystem conventions — explicitness wins over magic
// for an admin console where every route is a security boundary.
import { createRouter, createWebHistory } from 'vue-router'
import { isAuthenticated, loadSession, sessionChecked } from '@/stores/auth.js'

const routes = [
 { path: '/ha', name: 'ha', component: () => import('@/views/HAView.vue'), meta: { requiresAuth: true } },
  {
    // The landing screen is a summary, not a list.
    //
    // /devices assumed the admin knew what they were looking for. The
    // questions they arrive with — how many are live, is the gateway
    // up, is anything stuck — took three screens and counting by eye.
    path: '/',
    name: 'overview',
    component: () => import('../views/OverviewView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/login',
    name: 'login',
    component: () => import('@/views/LoginView.vue'),
  },
  {
    path: '/devices',
    name: 'devices',
    component: () => import('@/views/DevicesView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/nodes',
    name: 'nodes',
    component: () => import('@/views/NodesView.vue'),
    meta: { requiresAuth: true },
  },
  {
    // Next to 정책, because it is the same subject seen whole.
    path: '/reach',
    name: 'reach',
    component: () => import('../views/ReachView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/policies',
    name: 'policies',
    component: () => import('@/views/PoliciesView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/audit',
    name: 'audit',
    component: () => import('@/views/AuditView.vue'),
    meta: { requiresAuth: true },
  },
  {
    // Account details and the password-change entry point.
    //
    // requiresAuth like everything else: there is nothing here for an
    // anonymous visitor, and the claims it renders come from the token.
    path: '/enrollment-requests',
    name: 'enrollment-requests',
    component: () => import('@/views/EnrollmentRequestsView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/groups',
    name: 'groups',
    component: () => import('@/views/GroupsView.vue'),
    meta: { requiresAuth: true },
  },
  {
    path: '/trace',
    name: 'trace',
    component: () => import('@/views/TraceView.vue'),
    meta: { requiresAuth: true },
  },
  {
    // Catch-all: send unknown URLs to the dashboard.
    path: '/:pathMatch(.*)*',
    redirect: '/',
  },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
})

// Auth guard. On first navigation ask the server who we are (the
// session is a cookie the page cannot read); after that the store
// knows. Unauthenticated → the login route, with where to return.
router.beforeEach(async (to) => {
  if (!sessionChecked.value) await loadSession()
  if (to.meta.requiresAuth && !isAuthenticated.value) {
    return { name: 'login', query: to.fullPath !== '/' ? { next: to.fullPath } : {} }
  }
  if (to.name === 'login' && isAuthenticated.value) {
    return { name: 'overview' }
  }
})

export default router
