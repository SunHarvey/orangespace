const timestamps = new Set(['created_at', 'expires_at', 'valid_until', 'last_seen_at', 'observed_at', 'committed_at', 'enforcement_deadline', 'revoked_at', 'approved_at'])
const utc = new Intl.DateTimeFormat('zh-CN', {
  timeZone: 'UTC', year: 'numeric', month: 'long', day: 'numeric',
  hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23',
})

export function formatCell(key: string, value: unknown): string {
  if (value === null || value === undefined) return '—'
  if (timestamps.has(key)) {
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < 0) return '未知'
    const date = new Date(value * 1000)
    return Number.isNaN(date.getTime()) ? '未知' : `${utc.format(date)} UTC`
  }
  return Array.isArray(value) ? value.join('、') : String(value)
}
