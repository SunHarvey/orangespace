import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
export default defineConfig({plugins:[vue()],server:{host:'127.0.0.1',proxy:{'/control/v1':{target:process.env.CONTROL_API_ORIGIN || 'http://127.0.0.1:8090',changeOrigin:false,secure:true,followRedirects:false}}},test:{environment:'jsdom'}})
