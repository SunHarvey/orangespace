import { it, expect, vi } from 'vitest'
import { createSession } from '../src/session'
import { ApiClient } from '../src/api'
import { createConsoleRouter } from '../src/router'
const reply = {schema:1,access_token:'x'.repeat(43),token_type:'bearer',central_session_id:'11111111-1111-4111-8111-111111111111',expires_at:1999999999,user:{central_user_id:'11111111-1111-4111-8111-111111111111',username:'u',role:'user',enabled:true,user_epoch:1,created_at:1}}
it('单元：角色路由拒绝普通用户访问管理员页，刷新不恢复token', async()=>{
 const api = new ApiClient(vi.fn().mockImplementation(async()=>new Response(JSON.stringify(reply))))
 const s=createSession(api); const r=createConsoleRouter(s,true)
 await r.push('/users'); expect(r.currentRoute.value.path).toBe('/login')
 await s.login('u','password'); await r.push('/users'); expect(r.currentRoute.value.path).toBe('/nodes')
 expect(createSession(api).current.value).toBeNull()
 expect(localStorage.length).toBe(0); expect(sessionStorage.length).toBe(0)
 s.clear()
})
it('单元：退出即使后端失败也清内存但报告撤销未确认',async()=>{
 const f=vi.fn().mockImplementation(async()=>new Response(JSON.stringify(reply)))
 const api=new ApiClient(f); const s=createSession(api); await s.login('u','password')
 f.mockRejectedValue(new Error('secret')); await expect(s.logout()).rejects.toThrow('未确认')
 expect(s.current.value).toBeNull()
 f.mockImplementation(async()=>new Response(JSON.stringify({schema:1}))); await api.request('/session')
 expect(f.mock.calls.at(-1)![1].headers.Authorization).toBeUndefined()
})
