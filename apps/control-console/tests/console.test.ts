import { mount, flushPromises } from '@vue/test-utils'
import { it, expect, vi } from 'vitest'
import ConsolePage from '../src/ConsolePage.vue'
import { ApiClient } from '../src/api'

it('单元：已有授权的用户和节点不可在操作弹窗改写',async()=>{
 const user='11111111-1111-4111-8111-111111111111', node='22222222-2222-4222-8222-222222222222'
 const grant={central_user_id:user,node_id:node,grant_id:'33333333-3333-4333-8333-333333333333',grant_epoch:3,enabled:true,scopes:['tunnel'],valid_until:null}
 const f=vi.fn().mockImplementation(async(_url,init)=>new Response(JSON.stringify(init.method==='PUT'?{schema:1,revocation:{cleanup_state:'pending'}}:{schema:1,items:[grant],next_cursor:null})))
 const w=mount(ConsolePage,{props:{section:'grants',admin:true,api:new ApiClient(f)}});await flushPromises()
 await w.findAll('tbody button')[1].trigger('click')
 const identityFields=w.findAll('.operation label').filter(l=>['中心用户UUID','节点UUID'].some(name=>l.text().startsWith(name)))
 expect(identityFields.length).toBe(0)
 await w.get('[data-reason]').setValue('fixture scoped revoke')
 await w.get('[data-confirm-input]').setValue(user+' / '+node)
 await w.get('[data-confirm-submit]').trigger('click');await flushPromises()
 const puts=f.mock.calls.filter(c=>c[1].method==='PUT')
 expect(puts.length).toBe(1)
 expect(puts[0][0]).toBe('/control/v1/admin/users/'+user+'/nodes/'+node+'/grant')
 expect(JSON.parse(puts[0][1].body)).toMatchObject({expected_grant_epoch:3,enabled:false})
 w.unmount()
})

it('单元：新授权按最终用户与节点确认，改变对象使旧确认失效',async()=>{
 const user='11111111-1111-4111-8111-111111111111',a='22222222-2222-4222-8222-222222222222',b='33333333-3333-4333-8333-333333333333'
 const f=vi.fn().mockImplementation(async(_url,init)=>new Response(JSON.stringify(init.method==='PUT'?{schema:1}:{schema:1,items:[],next_cursor:null})))
 const w=mount(ConsolePage,{props:{section:'grants',admin:true,api:new ApiClient(f)}});await flushPromises()
 await w.findAll('.toolbar button').find(x=>x.text().startsWith('新授权'))!.trigger('click')
 const input=(label:string)=>w.findAll('.operation label').find(x=>x.text().startsWith(label))!.get('input')
 await input('中心用户UUID').setValue(user);await input('节点UUID').setValue(a)
 expect(w.get('.operation').text()).toContain(user+' / '+a)
 await w.get('[data-reason]').setValue('fixture exact target')
 await w.get('[data-confirm-input]').setValue(user+' / '+a)
 expect((w.get('[data-confirm-submit]').element as HTMLButtonElement).disabled).toBe(false)
 await input('节点UUID').setValue(b)
 expect((w.get('[data-confirm-submit]').element as HTMLButtonElement).disabled).toBe(true)
 await w.get('[data-confirm-submit]').trigger('click');await flushPromises()
 expect(f.mock.calls.some(c=>c[1].method==='PUT')).toBe(false)
 await w.get('[data-confirm-input]').setValue(user+' / '+b)
 await w.get('[data-confirm-submit]').trigger('click');await flushPromises()
 expect(f.mock.calls.filter(c=>c[1].method==='PUT').map(c=>c[0])).toEqual(['/control/v1/admin/users/'+user+'/nodes/'+b+'/grant'])
 w.unmount()
})
it('单元：用户列表来自API并对精确对象禁用，响应后重读，不伪造成功', async()=>{
 const user={central_user_id:'11111111-1111-4111-8111-111111111111',username:'alice',role:'user',enabled:true,user_epoch:3,created_at:1}
 const f=vi.fn().mockImplementation(async(_url,init)=>new Response(JSON.stringify(init.method==='PATCH'?{schema:1,user,revocation:{schema:1,cleanup_state:'pending'}}:{schema:1,items:[user],next_cursor:null})))
 const w=mount(ConsolePage,{props:{section:'users',admin:true,api:new ApiClient(f)}}); await flushPromises()
 expect(w.text()).toContain('alice'); await w.get('[data-action="disable"]').trigger('click')
 expect(w.text()).toContain(user.central_user_id)
 await w.get('[data-confirm-input]').setValue(user.central_user_id); await w.get('[data-reason]').setValue('测试禁用'); await w.get('[data-confirm-submit]').trigger('click'); await flushPromises()
 expect(f.mock.calls.some(c=>c[1].method==='PATCH' && JSON.parse(c[1].body).expected_user_epoch===3)).toBe(true)
 expect(f.mock.calls.filter(c=>c[1].method==='GET').length).toBe(2)
 expect(w.text()).toContain('pending'); expect(w.text()).not.toContain('实际停止已完成')
})
it('单元：接口503明确未就绪，无静态用户',async()=>{
 const w=mount(ConsolePage,{props:{section:'users',admin:true,api:new ApiClient(vi.fn().mockResolvedValue(new Response('',{status:503})))}})
 await flushPromises(); expect(w.text()).toContain('503'); expect(w.text()).toContain('未就绪'); expect(w.text()).not.toContain('alice')
})
