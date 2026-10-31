import { it, expect } from 'vitest'
import { formatCell } from '../src/format'
it('epoch秒转中文日期，版本epoch保持整数，null不变成1970',()=>{expect(formatCell('created_at',1)).toContain('1970年');expect(formatCell('expires_at',1)).toContain('UTC');expect(formatCell('user_epoch',3)).toBe('3');expect(formatCell('valid_until',null)).toBe('—')})
