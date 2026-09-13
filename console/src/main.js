// AidotVpn admin console entry point.
//
// Initialization order is intentional:
//
//   1. Bootstrap CSS/JS — must load before App.vue mounts so component
//      styles cascade correctly.
//   2. Auth bootstrap — pull a stashed token (post-OIDC redirect) before
//      Vue Router's first navigation runs.
//   3. createApp + router + mount.
import 'bootstrap/dist/css/bootstrap.min.css'
// After Bootstrap, so the tokens win. See styles/console.css.
import './styles/console.css'
import 'bootstrap/dist/js/bootstrap.bundle.min.js'

import { createApp } from 'vue'
import App from './App.vue'
import router from './router/index.js'
import { loadSession } from './stores/auth.js'

// Who is signed in, before the router decides anything. The session is
// an HttpOnly cookie, so the answer has to come from the server.
await loadSession()

const app = createApp(App)
app.use(router)
app.mount('#app')
