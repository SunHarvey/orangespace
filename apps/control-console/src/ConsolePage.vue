<script setup lang="ts">
import { computed, ref, watch, onBeforeUnmount } from 'vue'
import { ApiClient, ApiError } from './api'
import { formatCell } from './format'
const props=defineProps<{section:string;admin:boolean;api:ApiClient}>()
const emit=defineEmits<{unauthorized:[]}>()
type Row=Record<string,any>
type Field={key:string;label:string;kind?:string;value:any}
type Operation={title:string;target:string;path:string;method:string;fields:Field[];fixed:Row;secret?:boolean}
const rows=ref<Row[]>([]), cursor=ref<string|null>(null), error=ref(''), busy=ref(false), result=ref(''), secret=ref(''), confirmation=ref(''), operation=ref<Operation|null>(null)
let secretTimer:ReturnType<typeof setTimeout>|undefined
let version=0
const columnNames:Record<string,string>={central_user_id:'中心用户ID',username:'用户名',role:'角色',enabled:'启用',user_epoch:'用户epoch',node_id:'节点ID',alias:'别名',display_name:'名称',api_origin:'HTTPS地址',tls_server_name:'TLS名称',state:'服务端状态',node_epoch:'节点epoch',config_revision:'配置revision',key_fingerprint:'公钥指纹',last_seen_at:'中心最近收到心跳',online:'中心判定在线',grant_id:'授权ID',grant_epoch:'授权epoch',scopes:'权限',valid_until:'授权截止(epoch秒)',central_session_id:'中心会话ID',session_id:'会话ID',expires_at:'过期(epoch秒)',sandbox_id:'沙盒ID',generation:'代次',tunnel_id:'隧道ID',lease_id:'租约ID',cleanup_state:'清理状态',enrollment_id:'注册ID',event_id:'事件ID',audit_event_id:'审计ID',action:'动作',actor_id:'操作者',object_id:'对象',request_id:'请求ID',created_at:'创建时间',reason:'理由'}
function base() { if(props.section==='nodes') return props.admin?'/admin/nodes':'/me/nodes'; if(props.section==='enrollments') return '/admin/node-enrollments'; return ['users','grants','audit-events'].includes(props.section)?'/admin/'+props.section:'/'+props.section }
function forget() { secret.value=''; clearTimeout(secretTimer) }
function fail(e:unknown) { error.value=e instanceof Error?e.message:'请求失败'; if(e instanceof ApiError && e.status===401) emit('unauthorized') }
async function load(append=false) {
 const run=++version; busy.value=true; error.value=''; forget()
 try { const next=append?cursor.value:null; const data=await props.api.request(base()+'?limit=50'+(next?'&cursor='+encodeURIComponent(next):'')); if(run!==version)return
 if(!Array.isArray(data.items) || !(data.next_cursor===null || typeof data.next_cursor==='string')) throw new Error('列表协议错误：接口未就绪')
 rows.value=append?[...rows.value,...data.items]:data.items; cursor.value=data.next_cursor
 } catch(e) { if(run===version){ rows.value=[]; cursor.value=null; fail(e) } } finally { if(run===version)busy.value=false }
}
watch(()=>props.section,()=>{ operation.value=null; result.value=''; rows.value=[]; cursor.value=null; void load() },{immediate:true})
onBeforeUnmount(()=>{version++;forget()})
const field=(key:string,label:string,value:any='',kind='text'):Field=>({key,label,value,kind})
function open(op:Operation) { forget(); result.value=''; error.value=''; confirmation.value=''; operation.value=op }
function start(kind:string,row:Row={}) {
 const id=String(row.central_user_id ?? row.node_id ?? row.grant_id ?? row.central_session_id ?? row.session_id ?? row.tunnel_id ?? '')
 const reason=field('reason','操作理由（必填）')
 if(kind==='create') return open({title:'创建用户',target:'创建用户',path:'/admin/users',method:'POST',fixed:{},fields:[field('username','用户名'),field('password','初始密码','','password'),field('role','角色 user 或 admin','user')]})
 if(kind==='disable'||kind==='reset') return open({title:kind==='disable'?'禁用用户':'重置密码',target:id,path:'/admin/users/'+encodeURIComponent(id)+(kind==='reset'?'/reset-password':''),method:kind==='reset'?'POST':'PATCH',fixed:{expected_user_epoch:row.user_epoch,...(kind==='disable'?{enabled:false}:{})},fields:[...(kind==='reset'?[field('password','新密码','','password')]:[]),reason]})
 if(kind==='enroll') return open({title:'创建一次性节点注册',target:'新节点注册',path:'/admin/node-enrollments',method:'POST',secret:true,fixed:{},fields:[field('node_id','节点UUID'),field('alias','别名'),field('display_name','显示名称'),field('api_origin','预期HTTPS origin'),field('tls_server_name','TLS名称'),field('expected_key_fingerprint','独立可信通道核对的公钥指纹'),reason]})
 if(kind==='activate'||kind==='suspend') return open({title:kind==='activate'?'审核激活：已独立核验TLS与公钥部署':'停用节点',target:id,path:'/admin/nodes/'+encodeURIComponent(id)+'/'+kind,method:'POST',fixed:{expected_node_epoch:row.node_epoch,...(kind==='activate'?{expected_config_revision:row.config_revision}:{})},fields:[reason]})
 if(kind==='address') return open({title:'修改地址/TLS（将停用，需重新核验）',target:id,path:'/admin/nodes/'+encodeURIComponent(id),method:'PATCH',fixed:{expected_config_revision:row.config_revision},fields:[field('api_origin','HTTPS origin',row.api_origin),field('tls_server_name','TLS名称',row.tls_server_name),field('display_name','名称',row.display_name),reason]})
 if(kind==='grant'||kind==='revoke') return open({title:kind==='revoke'?'撤销授权':'保存授权',target:row.grant_id?String(row.central_user_id)+' / '+String(row.node_id):'新授权',path:'grant',method:'PUT',fixed:{expected_grant_epoch:row.grant_epoch??0,enabled:kind!=='revoke',...(row.grant_id?{central_user_id:row.central_user_id,node_id:row.node_id}:{})},fields:[...(row.grant_id?[]:[field('central_user_id','中心用户UUID'),field('node_id','节点UUID')]),field('scopes','权限，逗号分隔',(row.scopes??['files.read']).join(',')),field('valid_until','截止epoch秒（留空不限期）',row.valid_until??'','number'),reason]})
 if(kind==='stop-session') return open({title:'撤销精确会话',target:id,path:'/sessions/'+encodeURIComponent(id),method:'DELETE',fields:[],fixed:{}})
 if(kind==='stop-lease') return open({title:'撤销精确租约（不提升整个授权epoch）',target:String(row.node_id)+' / '+String(row.tunnel_id),path:'/nodes/'+encodeURIComponent(row.node_id)+'/leases/'+encodeURIComponent(row.tunnel_id),method:'DELETE',fields:[],fixed:{}})
}
function validUuid(v:unknown) { return typeof v==='string' && /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(v) && v!=='00000000-0000-0000-0000-000000000000' }
const confirmationTarget=computed(()=>{
 const op=operation.value
 if(!op)return ''
 if(op.path!=='grant'||op.fixed.central_user_id)return op.target
 const user=op.fields.find(f=>f.key==='central_user_id')?.value
 const node=op.fields.find(f=>f.key==='node_id')?.value
 return validUuid(user)&&validUuid(node)?user+' / '+node:''
})
async function submit() {
 const op=operation.value; if(!op || !confirmationTarget.value || confirmation.value!==confirmationTarget.value || busy.value)return
 busy.value=true; error.value=''; forget()
 const payload:Row={schema:1,...op.fixed}
 try {
 for(const f of op.fields) { if(f.key!=='valid_until' && !String(f.value).trim()) throw new Error('请填写'+f.label); payload[f.key]=f.value }
 for(const k of ['central_user_id','node_id']) if(k in payload && !validUuid(payload[k])) throw new Error('UUID必须为非零canonical小写字符串')
 if(payload.api_origin) { const u=new URL(payload.api_origin); if(u.protocol!=='https:' || u.origin!==payload.api_origin || u.username || u.password) throw new Error('节点地址须为不含路径/凭据的HTTPS origin') }
 if(payload.role && !['admin','user'].includes(payload.role))throw new Error('角色仅限admin/user')
 if('valid_until' in payload) { const v=String(payload.valid_until); if(v!=='' && !/^[0-9]+$/.test(v))throw new Error('截止时间必须为整数epoch秒'); payload.valid_until=v===''?null:Number(v); if(payload.valid_until!==null && (!Number.isSafeInteger(payload.valid_until)||payload.valid_until<0))throw new Error('截止时间超出范围') }
 let path=op.path
 if(path==='grant') {path='/admin/users/'+payload.central_user_id+'/nodes/'+payload.node_id+'/grant'; delete payload.central_user_id; delete payload.node_id; payload.scopes=String(payload.scopes).split(',').map(s=>s.trim()); if(!payload.scopes.length || payload.scopes.some((s:string)=>!['files.read','files.write','tunnel'].includes(s)))throw new Error('权限不符合契约') }
 const response=await props.api.request(path,op.method,op.method==='DELETE'?undefined:payload)
 // Password fields are dropped immediately, including when a subsequent read fails.
 for(const f of op.fields) if(f.kind==='password') f.value=''
 operation.value=null
 const rev=response.revocation ?? (response.revocation_id?response:null)
 result.value=rev?'控制面已受理撤销；清理状态：'+String(rev.cleanup_state)+'；仅回执，不代表实际停止。':'控制面已返回；正在重读列表。'
 await load()
 if(op.secret && typeof response.enrollment_token==='string') { secret.value=response.enrollment_token; secretTimer=setTimeout(forget,Math.min(600000,Math.max(0,response.expires_at*1000-Date.now()))); result.value='一次性注册凭据，仅本次显示；关闭/刷新即丢失。注册ID：'+response.enrollment_id }
 } catch(e) { for(const f of op.fields) if(f.kind==='password') f.value=''; fail(e) } finally { busy.value=false }
}
function columns() { return Object.keys(columnNames).filter(k=>rows.value.some(r=>k in r)) }
</script>
<template>
<section aria-label="控制台数据">
 <div class="toolbar"><button :disabled="busy" @click="load()">刷新真实数据</button><button v-if="section==='users'&&admin" @click="start('create')">创建用户</button><button v-if="section==='enrollments'&&admin" @click="start('enroll')">新建注册</button><button v-if="section==='grants'&&admin" @click="start('grant')">新授权（初始epoch=0）</button></div>
 <p v-if="error" role="alert" class="error">{{error}}</p><p v-if="busy" role="status">请求中…</p><p v-if="result" role="status">{{result}}</p>
 <aside v-if="secret" class="secret"><strong>一次性 enrollment secret（仅当前操作，不记录）</strong><code>{{secret}}</code><button @click="forget">关闭并清除</button></aside>
 <p v-if="section==='nodes'" class="notice">在线仅由中心心跳接收判定；缺失 online 字段表示未知，不由浏览器推算。pending ≠ 已核验。地址/TLS变更需重新审批。</p>
 <p v-if="['leases','sandboxes'].includes(section)" class="notice">process_started = 仅进程启动；authenticated = 认证完成；forward_verified = 实际转发已证明。中心记录不证明持续转发/WFP隔离。沙盒停止接口未定义，请按精确租约撤销；不删除本地或远端文件。</p>
 <div class="table-scroll"><table v-if="rows.length"><thead><tr><th v-for="c in columns()" :key="c">{{columnNames[c]}}</th><th>操作</th></tr></thead><tbody><tr v-for="(r,i) in rows" :key="i"><td v-for="c in columns()" :key="c">{{formatCell(c,r[c])}}</td><td class="actions">
 <template v-if="section==='users'&&admin"><button data-action="disable" :disabled="!r.enabled" @click="start('disable',r)">禁用</button><button @click="start('reset',r)">重置密码</button></template>
 <template v-if="section==='nodes'&&admin"><button @click="start('activate',r)">审核激活</button><button @click="start('suspend',r)">停用</button><button @click="start('address',r)">地址/TLS</button></template>
 <template v-if="section==='grants'&&admin"><button @click="start('grant',r)">修改截止/权限</button><button @click="start('revoke',r)">撤销</button></template>
 <button v-if="section==='sessions'" @click="start('stop-session',r)">撤销会话</button><button v-if="section==='leases'" @click="start('stop-lease',r)">停止此租约</button>
 </td></tr></tbody></table><p v-else-if="!busy&&!error">服务端返回空列表</p></div>
 <button v-if="cursor" :disabled="busy" @click="load(true)">加载下一页（尚有更多，未视为完整列表）</button>
 <form v-if="operation" class="operation" @submit.prevent="submit"><h3>{{operation.title}}</h3><p>精确对象：<code>{{confirmationTarget || '请先填写有效的用户与节点UUID'}}</code></p><p>预期版本：{{JSON.stringify(operation.fixed)}}</p><label v-for="f in operation.fields" :key="f.key">{{f.label}}<input v-model="f.value" :type="f.kind||'text'" :data-reason="f.key==='reason'?true:undefined" :autocomplete="f.kind==='password'?'new-password':'off'" :required="f.key!=='valid_until'"></label><label>输入上方精确对象确认<input v-model="confirmation" data-confirm-input autocomplete="off" required></label><button data-confirm-submit @click.prevent="submit" :disabled="busy||!confirmationTarget||confirmation!==confirmationTarget">确认执行</button><button type="button" @click="operation=null;forget()">取消</button></form>
</section>
</template>
