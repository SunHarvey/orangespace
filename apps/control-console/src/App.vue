<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import ConsolePage from './ConsolePage.vue'
import type { ApiClient } from './api'
import type { ConsoleSession } from './session'
import { menus } from './router'
import logo from './assets/orangespace-logo-approved.png'
const props=defineProps<{api:ApiClient;session:ConsoleSession}>()
const route=useRoute(), router=useRouter()
const username=ref(''), password=ref(''), busy=ref(false), error=ref('')
const current=computed(()=>props.session.current.value)
const admin=computed(()=>current.value?.user.role==='admin')
const section=computed(()=>route.path.slice(1))
const visibleMenus=computed(()=>menus.filter(m=>!m.admin||admin.value))
watch(current,s=>{if(!s)void router.replace('/login')})
async function login(){if(busy.value)return;busy.value=true;error.value='';try{await props.session.login(username.value,password.value);await router.replace('/nodes')}catch(e){error.value=e instanceof Error?e.message:'登录失败'}finally{password.value='';busy.value=false}}
async function logout(){error.value='';try{await props.session.logout()}catch(e){error.value=e instanceof Error?e.message:'撤销未确认'}finally{await router.replace('/login')}}
function unauthorized(){props.session.clear();void router.replace('/login')}
</script>
<template>
<div class="shell" :class="{'login-shell':!current}">
 <aside class="sidebar"><div class="brand"><img :src="logo" alt="橙域 OrangeSpace 原Logo"><div><strong>橙域</strong><small>OrangeSpace · 控制台</small></div></div>
 <template v-if="current"><nav aria-label="控制台菜单"><RouterLink v-for="m in visibleMenus" :key="m.id" :to="'/'+m.id">{{m.name}}</RouterLink></nav><div class="identity">{{current.user.username}} · {{admin?'管理员':'普通用户'}}<button @click="logout">退出登录</button></div></template>
 <p v-else class="tagline">远方的网络，<br>眼前的工作空间。</p>
 </aside>
 <main><p v-if="error" role="alert" class="error">{{error}}</p>
 <form v-if="!current" class="login-card" @submit.prevent="login"><span class="eyebrow">CONTROL CONSOLE</span><h1>登录管理控制台</h1><p>使用中心账号登录，所有权限由服务端校验。</p><label>用户名<input v-model="username" name="username" autocomplete="username" required maxlength="128"></label><label>密码<input v-model="password" name="password" type="password" autocomplete="current-password" required></label><button class="primary" :disabled="busy">{{busy?'正在验证…':'登录'}}</button><p class="notice">令牌仅保存在当前页面内存，刷新需重新登录。不提供默认账号。</p></form>
 <template v-else><header><span class="eyebrow">ORANGESPACE / CONTROL</span><h1>{{menus.find(m=>m.id===section)?.name||'控制台'}}</h1><p>真实控制面数据 · 不以页面状态代替实际执行证明</p></header><ConsolePage v-if="route.path!=='/login'" :section="section" :admin="admin" :api="api" @unauthorized="unauthorized"/><footer>前端菜单仅辅助导航；身份、角色、对象归属与版本均由后端验证。</footer></template>
 </main>
</div>
</template>
