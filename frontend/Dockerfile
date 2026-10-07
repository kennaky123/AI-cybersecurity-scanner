FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

EXPOSE 5173

ENV VITE_BACKEND_URL=http://backend:8000

CMD ["npm", "run", "dev", "--", "--host", "0.0.0.0"]
