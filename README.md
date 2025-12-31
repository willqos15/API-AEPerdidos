# Backend – Achados e Perdidos (API REST)


API backend do projeto Achados e Perdidos, responsável por autenticação, cadastro, busca, edição, exclusão de itens e upload de imagens utilizando **MongoDB** e **Cloudinary**. O backend é independente do frontend e funciona como uma API REST.

---

## Frontend

Este repositório contém apenas o **backend** da aplicação.

O código do **frontend em React** está disponível em um repositório separado no GitHub:

 **Frontend – Achados e Perdidos**  
(https://github.com/willqos15/Achados-e-Perdidos)

O frontend consome essa API para autenticação, listagem e gerenciamento dos itens.

---

##  Tecnologias usadas
```
- Node.js
- Express
- MongoDB (Mongoose)
- JWT (autenticação)
- Bcrypt (criptografia de senha)
- Multer (upload de arquivos)
- Cloudinary (armazenamento de imagens)
- Dotenv
- CORS
```
---

## Dependências

O projeto utiliza as seguintes bibliotecas no backend: Express, CORS, Dotenv, Mongoose, Bcrypt, JSON Web Token, Multer e Cloudinary.

Todas as dependências já estão configuradas no `package.json`.

---

### Instalação

Caso ainda não tenha, instale o Node.js (versão LTS):
https://nodejs.org

Em seguida, abra o terminal na pasta do projeto e execute:
`npm install`

---

### Configuração do projeto:  
No package.json é necessário habilitar ES Modules adicionando `"type": "module"`.

---
### Configuração de CORS (Importante)

A API utiliza **CORS com origem controlada** para permitir requisições apenas do frontend autorizado.

Por padrão, o backend está configurado para aceitar requisições do frontend em **produção (Vercel)**.  
Para **testes locais**, é necessário ajustar manualmente essa configuração.

No arquivo principal do servidor, existe o seguinte trecho:

```js
const app = express()
app.use(cors({
    origin: "https://achados-e-perdidos-gray.vercel.app"
    // origin: "http://localhost:5173"
}))
```

Comente a URL da Vercel e descomente o `http://localhost:5173`


---

### Variáveis de ambiente (.env)

Crie um arquivo `.env` na raiz do projeto com as seguintes variáveis:
```BdUrl=mongodb+srv://USUARIO:SENHA@cluster.mongodb.net/nomedobanco  
jwtsecret=sua_chave_secreta_jwt  
testelogin=admin@email.com  
testesenha=$2b$12$HASH_DA_SENHA  
CLOUDINARY_NAME=seu_cloud_name  
CLOUDINARY_KEY=sua_api_key  
CLOUDINARY_SECRET=seu_api_secret
```

A senha utilizada no login precisa estar criptografada com bcrypt. Exemplo para gerar o hash:
`const senhahash = await bcrypt.hash("suasenha", 12)`
Cole o hash gerado na variável `testesenha` do `.env`.

---

### Para rodar o projeto:
`node server.js`
O servidor será iniciado em http://localhost:3000.

---

#### Autenticação:  
A API utiliza JWT via Authorization Header no formato:
`Authorization: Bearer SEU_TOKEN_AQUI`
Rotas protegidas exigem token válido. O token expira em 15 minutos. O logout é controlado no frontend removendo o token armazenado.

---

### Rotas disponíveis:
```POST /testelogin → realiza login e gera token  
GET /testelogin → verifica se o usuário está logado  
POST /atualizatoken → gera um novo token válido  
POST /upload → upload de imagem para o Cloudinary (rota protegida)  
DELETE /imgdel/:public_id → remove imagem do Cloudinary  
GET /perdidos → lista todos os itens cadastrados  
GET /busca/:nome → busca itens por nome (parcial, case-insensitive)  
POST /cadastro → cria um novo item (máximo de 5 itens, rota protegida)  
PUT /perdidos/:id → atualiza um item existente (rota protegida)  
DELETE /perdidos/:id → remove item e imagem associada (rota protegida)
```

---

### Model de dados (MongoDB / Mongoose):
```const itemnovoSchema = new mongoose.Schema({
  nome: String,
  descricao: String,
  local: String,
  proprietario: String,
  contato: String,
  encontrado: Boolean,
  foto: String,
  public_idfoto: String
})
export default mongoose.model('itens', itemnovoSchema)
```

---

### Observações de segurança:  
O login de administrador é controlado via variáveis de ambiente e não por usuários cadastrados em banco.  
Os tokens possuem tempo de expiração curto.  
Não há uso de cookies, apenas Bearer Token.  

Este repositório contém apenas o backend. O frontend do projeto está disponível em um repositório separado no GitHub.

---
##  Estrutura do projeto
```
├── index.js # Arquivo principal do servidor
├── itemnovo.js # Model (Schema) do MongoDB
├── .env # Variáveis de ambiente (não versionar)
├── package.json
├── anotacoes.js # Anotações de estudos descartadas no projeto
├── Usuario.js # Schema de estudo descartado no projeto

```
---

## 👨‍💻 Sobre o autor

Desenvolvido por William Queiroz
🔗 Portfólio: (https://queirozdeveloper.vercel.app/)

