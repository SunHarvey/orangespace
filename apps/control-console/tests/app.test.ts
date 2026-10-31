import { mount, flushPromises } from '@vue/test-utils'
import { it, expect, vi } from 'vitest'
import App from '../src/App.vue'
import { ApiClient } from '../src/api'
import { createSession } from '../src/session'
import { createConsoleRouter } from '../src/router'
it('组件单元mock：登录连接ApiClient、菜单及真实HTTP错误，不证明后端联调', async()=>{
 const f=vi.fn().mockImplementation(async(url:string)=>url.endsWith('/auth/login')?new Response(JSON.stringify({schema:1,access_token:'x'.repeat(43),token_type:'bearer',central_session_id:'11111111-1111-4111-8111-111111111111',expires_at:1999999999,user:{username:'admin',role:'admin',enabled:true}})):new Response('',{status:503}))
 const api=new ApiClient(f), session=createSession(api), router=createConsoleRouter(session,true)
 await router.push('/login'); const w=mount(App,{props:{api,session},global:{plugins:[router]}})
 expect(w.get('img').attributes('src')).toContain('orangespace-logo-approved')
 await w.get('[name="username"]').setValue('admin'); await w.get('[name="password"]').setValue('secret'); await w.get('form').trigger('submit'); await flushPromises()
 expect(w.text()).toContain('HTTP 503'); expect(w.findAll('nav a')).toHaveLength(8)
 expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0)
 session.clear(); w.unmount()
})
