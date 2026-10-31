export interface User { central_user_id: string; username: string; role: 'admin' | 'user'; enabled: boolean; user_epoch: number; created_at: number }
export interface Session { central_session_id: string; expires_at: number; user: User }
export class ApiError extends Error { constructor(public status: number, message: string) { super(message) } }
export class ApiClient {
 private token: string | null = null
 private authGeneration = Symbol()
 constructor(private fetcher: typeof fetch = fetch) {}
 clear() { this.token = null; this.authGeneration = Symbol() }
 async login(username: string, password: string): Promise<Session> {
  this.clear()
  const data = await this.request('/auth/login', 'POST', { schema: 1, username, password })
  if (!/^[A-Za-z0-9_-]{43}$/.test(data.access_token) || data.token_type !== 'bearer' || !data.user || !['admin','user'].includes(data.user.role) || !data.user.enabled || !Number.isSafeInteger(data.expires_at) || data.expires_at * 1000 <= Date.now()) throw new ApiError(0, '登录协议错误')
  this.token = data.access_token
  this.authGeneration = Symbol()
  return { central_session_id: data.central_session_id, expires_at: data.expires_at, user: data.user }
 }
 async request(path: string, method = 'GET', body?: unknown): Promise<any> {
  if (!/^\/[a-zA-Z0-9/?=&%_.-]+$/.test(path) || path.includes('..') || path.startsWith('//')) throw new ApiError(0, '非法API路径')
  const token = this.token
  const authGeneration = this.authGeneration
  let response: Response
  try {
   response = await this.fetcher('/control/v1' + path, { method, redirect: 'error', cache: 'no-store', credentials: 'omit', signal: AbortSignal.timeout(15000), headers: { Accept: 'application/json', ...(body === undefined ? {} : { 'Content-Type': 'application/json' }), ...(token ? { Authorization: 'Bearer ' + token } : {}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }) })
  } catch { throw new ApiError(0, '网络/TLS/超时错误：控制面未就绪，请重试') }
  if (!response.ok) {
   if (response.status === 401 && authGeneration === this.authGeneration && token === this.token) this.clear()
   const labels: Record<number,string> = {401:'认证已失效，请重新登录',403:'无权限',404:'接口或对象未就绪/不可见',409:'版本冲突，请刷新后重试',410:'对象已终止',422:'输入不符合契约',426:'协议版本不支持',429:'请求过频',503:'依赖未就绪'}
   throw new ApiError(response.status, `HTTP ${response.status}：${labels[response.status] ?? '请求失败'}`)
  }
  let data: any
  try { data = await response.json() } catch { throw new ApiError(0, '协议错误：预期JSON') }
  if (!data || data.schema !== 1) throw new ApiError(0, '协议版本错误')
  return data
 }
}
