import { createRouter,createWebHashHistory,createMemoryHistory } from 'vue-router'
import { h } from 'vue'
import type { ConsoleSession } from './session'
export const menus=[{id:'nodes',name:'节点',admin:false},{id:'users',name:'用户',admin:true},{id:'enrollments',name:'节点注册',admin:true},{id:'grants',name:'授权',admin:true},{id:'sessions',name:'会话',admin:false},{id:'sandboxes',name:'沙盒',admin:false},{id:'leases',name:'租约',admin:false},{id:'audit-events',name:'审计',admin:true}]
export function createConsoleRouter(session:ConsoleSession,memory=false) {
 const view={render:()=>h('div')}
 const router=createRouter({history:memory?createMemoryHistory():createWebHashHistory(),routes:[{path:'/',redirect:'/nodes'},{path:'/login',component:view},...menus.map(m=>({path:'/'+m.id,component:view,meta:{admin:m.admin}})),{path:'/:pathMatch(.*)*',redirect:'/nodes'}]})
 router.beforeEach(to=>{ const s=session.current.value; if(to.path==='/login') return true; if(!s || s.expires_at*1000<=Date.now()) return '/login'; if(to.meta.admin && s.user.role!=='admin') return '/nodes'; return true })
 return router
}
