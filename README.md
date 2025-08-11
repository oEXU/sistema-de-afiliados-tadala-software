# sistema-de-afiliados-tadala-software
Sistema de afiliados extremamente foda feito belo genio exu que tem mais de 140QI, besta mecanica, geneticamente superior terror da emaclab. 

Passos de Instalação:

Crie uma pasta nova no seu servidor/computador, ex: sistema-referencia.

Abra o terminal nessa pasta e rode: npm init -y para criar package.json.

Instale dependências: npm install express sqlite3 body-parser jsonwebtoken bcrypt crypto cors express-rate-limit. 

Copie o código acima para um arquivo app.js na pasta. 

Altere SECRET_KEY para algo único e seguro (gere com node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"). 

Altere ADMIN_PASSWORD_HASH: Rode no Node REPL require('bcrypt').hashSync('sua_senha_forte', 10) e cole o hash. 

Rode o servidor: node app.js. 

Para produção: Use PM2 (npm install -g pm2; pm2 start app.js), configure HTTPS com Nginx/Apache, e rode em background. 

Segurança: Nunca exponha endpoints publicamente sem autenticação. Use firewall, atualize pacotes, e mude senhas. Para login de usuários normais, adicione um sistema de auth similar ao admin.
