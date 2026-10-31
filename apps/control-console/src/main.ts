import { createApp } from 'vue'
import App from './App.vue'
import { ApiClient } from './api'
import { createSession } from './session'
import { createConsoleRouter } from './router'
import './style.css'
const api=new ApiClient(), session=createSession(api)
const router=createConsoleRouter(session)
createApp(App,{api,session}).use(router).mount('#app')
