FROM node:22-alpine

WORKDIR /app

# 安装依赖
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# 复制源码和配置
COPY server.js ./
COPY public/ ./public/
COPY src/ ./src/
COPY config/ ./config/

EXPOSE 3001

ENV PORT=3001 \
    NODE_ENV=production

# 运行时数据卷：审计任务、报告、缓存
VOLUME ["/app/workspace"]

CMD ["node", "server.js"]
