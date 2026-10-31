import { shallowRef } from 'vue'
import { ApiClient, type Session } from './api'
export function createSession(api: ApiClient) {
 const current = shallowRef<Session|null>(null)
 let timer: ReturnType<typeof setTimeout> | undefined
 let generation=0
 function clear() { generation++; clearTimeout(timer); current.value=null; api.clear() }
 async function login(username:string,password:string) {
  clear(); const run=generation; const result=await api.login(username,password)
  if(run!==generation) { api.clear(); throw new Error('登录已取消') }
  current.value=result; timer=setTimeout(clear,Math.max(0,Math.min(3600000,result.expires_at*1000-Date.now())))
 }
 async function logout() {
  const id=current.value?.central_session_id
  const pending=id ? api.request('/sessions/'+encodeURIComponent(id),'DELETE') : Promise.resolve()
  clear()
  try { if(id) { const r=await pending; if(!r.revocation_id) throw new Error('invalid') } }
  catch { throw new Error('本地已退出；服务端撤销未确认，旧会话需等待过期或管理员撤销') }
 }
 return {current,clear,login,logout}
}
export type ConsoleSession=ReturnType<typeof createSession>
