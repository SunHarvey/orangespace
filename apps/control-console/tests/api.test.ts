import { describe,it,expect,vi } from 'vitest'
import { ApiClient } from '../src/api'

function loginResponse(token: string) {
 return new Response(JSON.stringify({schema:1,access_token:token,token_type:'bearer',central_session_id:'11111111-1111-4111-8111-111111111111',expires_at:1999999999,user:{central_user_id:'11111111-1111-4111-8111-111111111111',username:'fixture',role:'admin',enabled:true,user_epoch:1,created_at:1}}),{status:200})
}

function deferredResponse() {
 let resolve!: (response: Response) => void
 const promise = new Promise<Response>(done => { resolve = done })
 return { promise, resolve }
}

describe('401只失效所属的当前认证（合成凭据、可控fetch）',()=>{
 it.each(['different-token','same-token','anonymous'] as const)('迟到旧401不清除新登录：%s',async(kind)=>{
  const delayed = deferredResponse()
  const oldToken = 'a'.repeat(43)
  const newToken = kind === 'same-token' ? oldToken : 'b'.repeat(43)
  const fetcher = vi.fn<typeof fetch>()
  const api = new ApiClient(fetcher)
  if (kind !== 'anonymous') {
   fetcher.mockResolvedValueOnce(loginResponse(oldToken))
   await api.login('fixture','synthetic-password')
  }
  fetcher.mockReturnValueOnce(delayed.promise)
  const oldResult = api.request('/admin/users').catch(error => error)
  api.clear()
  fetcher.mockResolvedValueOnce(loginResponse(newToken))
  await api.login('fixture','synthetic-password')
  delayed.resolve(new Response(null,{status:401}))
  expect(await oldResult).toMatchObject({status:401})
  fetcher.mockResolvedValueOnce(new Response(JSON.stringify({schema:1}),{status:200}))
  await api.request('/session')
  const sent = new Headers(fetcher.mock.calls.at(-1)![1]?.headers).get('Authorization')
  expect(sent === 'Bearer ' + newToken).toBe(true)
 })
})
describe('真实请求边界（fetch替身仅单元证据）',()=>{
 it('登录使用schema1且内存Bearer只在header发送，禁止重定向',async()=>{
 const fetcher=vi.fn().mockImplementation(async()=>new Response(JSON.stringify({schema:1,access_token:'a'.repeat(43),token_type:'bearer',central_session_id:'11111111-1111-4111-8111-111111111111',expires_at:1999999999,user:{central_user_id:'11111111-1111-4111-8111-111111111111',username:'admin',role:'admin',enabled:true,user_epoch:1,created_at:1},nodes:[],nodes_next_cursor:null}),{status:200}))
 const api=new ApiClient(fetcher); await api.login('admin','secret'); await api.request('/session')
 expect(fetcher.mock.calls[0][0]).toBe('/control/v1/auth/login')
 expect(JSON.parse(fetcher.mock.calls[0][1].body)).toEqual({schema:1,username:'admin',password:'secret'})
 expect(fetcher.mock.calls[1][1]).toMatchObject({redirect:'error',cache:'no-store',credentials:'omit',headers:{Authorization:'Bearer '+'a'.repeat(43)}})
 expect(localStorage.length).toBe(0)
 })
 it('拒绝非schema1与HTTP错误，不展示服务器正文',async()=>{
 const api=new ApiClient(vi.fn().mockResolvedValue(new Response('secret-body',{status:503})))
 await expect(api.request('/session')).rejects.toThrow('503')
 const invalid=new ApiClient(vi.fn().mockResolvedValue(new Response(JSON.stringify({schema:2}),{status:200})))
 await expect(invalid.request('/session')).rejects.toThrow('协议')
 })
})
