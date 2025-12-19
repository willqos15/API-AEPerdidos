//npm init -y //para criar o package json do seu projeto com padrão ok
//npm iinsal mongodb
//npm install express //cria servidor e API
//npm install dotenv //puxa o arquivo env
// mudar no package.json o  "type": para "module" para permitir importar com import

// BIBLIOTECAS DO LOGIN DO USUARIO
//npm install bcrypt PARA FAZER CRIPTOGRAFIA DA SENHA
//npm install jsonwebtoken PARA USAR TOKEN DE AUTENTICAÇÃO

//GPT REMOVE import { MongoClient } from "mongodb"
import express from "express"
import cors from "cors" //complemento do express para permitir conexão local na API
import dotenv from "dotenv"
import mongoose from "mongoose"

//para o login
import bcrypt from "bcrypt"
import jwt from "jsonwebtoken"
import cookieParser from "cookie-parser"

dotenv.config() //procura o arquivo env de configuração

//Importa Scheema de cadastro post
import itens from "./itemnovo.js"

//instancia express na variavel app
const app = express()
app.use(cors({
    origin: "http://localhost:5173", credentials:true
}))

//Configura o express pra entender arquivos JSON - converte do boy para JSON
app.use(express.json())

import multer from "multer" //pra upload de imagem e arquivos em pacotses
import { v2 as cloudinary } from "cloudinary" //importa a biblioteca e a renomeia

cloudinary.config({
    cloud_name: process.env.CLOUDINARY_NAME,
    api_key: process.env.CLOUDINARY_KEY,
    api_secret: process.env.CLOUDINARY_SECRET
})



mongoose.connect(process.env.BdUrl)
    .then(() => {
        console.log("Conectado!")
    })
    .catch((erro) => {
        console.log("ERRO AO CONECTAR " + erro)
    })


//METODOS CRUD
import Usuario from './Usuario.js'


//REGISTRAR USUARIO
// app.post('/registrar', async (req, res) => {
//     const { name, email, password, confirmpassword } = req.body

//     if (!name) { return res.status(422).json({ msg: 'O nome é obrigatório' }) }
//     if (!email) { return res.status(422).json({ msg: 'O Email é obrigatório' }) }
//     if (!password) { return res.status(422).json({ msg: 'A senha é obrigatória' }) }
//     if (password !== confirmpassword) { return res.status(422).json({ msg: 'As senhas não batem' }) }

//     //se o usuario existe
//     const usuarioexiste = await Usuario.findOne({ email: email })
//     if (usuarioexiste) { return res.status(422).json({ msg: 'Utilize outro email' }) }

//     //criar senha criptografada
//     const salt = await bcrypt.genSalt(12) //gera caracteres aleatorios numa segurança nivel 12
//     const passwordHash = await bcrypt.hash(password, salt) //hash mistura a senha com gom genSalt

//     //cria Usuarios
//     const usuario = new Usuario({
//         name, email, password: passwordHash
//     })

//     try {
//         await usuario.save()
//         res.status(201).json({ msg: 'Usuário criado com sucesso!' })


//     }
//     catch (error) {
//         console.log(error)
//         res.status(500).json({ msg: 'Erro no servidor' })
//     }
// })


app.use(cookieParser())

function autenticar(req, res, next) {
    const mtoken = req.cookies.token
    if (!mtoken) return res.status(401).json({ msg: 'erro' })

    try {
        req.user = jwt.verify(mtoken, process.env.jwtsecret)
        next()
    } catch {
        //res.clearCookie("token", {httpOnly: true, sameSite: "strict"})
        return res.status(401).json({ msg: 'erro' }) }
}

//verifica se usuário está logado
app.get('/testelogin', autenticar, (req,res)=>{
    res.status(200).json({logado: true, nivel: req.user.nivel})
})

//sair da conta
app.post('/logout', (req,res)=>{
    res.clearCookie("token", {
        httpOnly: true, sameSite: "strict",  path: "/"
    })
    res.status(200).json({msg : "logout realizado com sucesso"})
})

app.post('/testelogin', async (req, res) => {
    const { email, password } = req.body
    if (!email || !password) { return res.status(422).json({ msg: 'Email e senha obrigatórios' }) }
    if (email === process.env.testelogin) {

        const comparasenha = await bcrypt.compare(password, process.env.testesenha)

        if (!comparasenha) { return res.status(401).json({ msg: 'SENHA INCORRETA' }) }

        const meutoken = jwt.sign( //sign cria um token (payload, secret, options)
            { nivel: "admin" }, process.env.jwtsecret, { expiresIn: "15m" })

        //envia um token por cookie
        res.cookie(
            "token", meutoken,
            {   path: "/",
                httpOnly: true, //oculta tokien do js
                sameSite: "strict", //segurança para excutar só no site
                //secure: true //só permite o envio via https, não permite localhost
            })

        res.status(200).json({ msg: "LOGIN COM SUCESSO" })


    } else { return res.status(400).json({ msg: 'LOGIN INCORRETO' }) }
})

//const senhahash = await bcrypt.hash("",12)
//console.log(senhahash)

app.post('/atualizatoken', (req, res) => {
    const token = req.cookies.token
    if (!token) return res.status(401).json({ msg: 'ERRO' })

    try {
        const dadostoken = jwt.verify(token, process.env.jwtsecret)
        const novotoken = jwt.sign(
            { nivel: dadostoken.nivel }, process.env.jwtsecret, { expiresIn: "15m" })

        res.cookie("token", novotoken, {
            httpOnly: true, sameSite: "strict"
            //,secure: true
        })

        res.status(200).json({ msg: 'okay' })

    } catch { res.status(401).json({ msg: 'erro' }) }

})


// app.post('/login', async (req, res) => {
//     const { email, password } = req.body
//     if (!email) { return res.status(422).json({ msg: 'Email obrigatório' }) }
//     if (!password) { return res.status(422).json({ msg: 'Senha obrigatória' }) }

//     const user = await Usuario.findOne({ email: email }) //nome do campo vindo do Schema: valor da variavel
//     if (!user) { res.status(404).json({ msg: 'Usuário não encontrado' }) }

//     const checarSenha = await bcrypt.compare(password, user.password)
//     if (!checarSenha) { return res.status(422).json({ msg: 'Senha inválida!' }) }

//     try {
//         const secret = process.env.SECRET
//         const token = jwt.sign(
//             { id: user._id },
//             secret,)
//         res.status(200).json({ msg: 'Autenticação feita com sucesso', token })
//     }
//     catch (erro) {
//         console.log(erro)
//         res.status(500).json({ msg: 'Erro no servidor' })
//     }
// })


// //Middleware
// function checaToken(req, res, next) {
//     const authHeader = req.headers['authorization']
//     const token = authHeader && authHeader.split(' ')[1]
//     if (!token) { return res.status(401).json({ msg: 'Acesso Negado' }) }

//     try {
//         const secret = process.env.SECRET
//         jwt.verify(token, secret)
//         next()
//     }
//     catch (erro) { res.status(400).json({ msg: 'Token inválido' }) }
// }

// app.get('/user/:id', checaToken, async (req, res) => {
//     const id = req.params.id
//     const user = await Usuario.findById(id, '-password')
//     if (!user) { return res.status(404).json({ msg: 'Usuario não encontrado' }) }
//     res.status(200).json({ user })
// })


//UPLOAD DE IMAGEM
const upload = multer({ storage: multer.memoryStorage() }) //deixa o arquivo na RAM temporariamente
app.post('/upload', upload.single('file'), (req, res) => { //o input no html tem que ter name='file'
    if (!req.file) {
        return res.status(400).json({ erro: "Sem arquivo" })
    }

    cloudinary.uploader.upload_stream( //permite pegar da RAM
        (erro, resultado) => {
            if (erro) return res.status(500).json(erro)
            res.json({ url: resultado.secure_url })
        }

    ).end(req.file.buffer)
})



//READ
app.get("/perdidos", (req, res) => {
    itens.find({})
        .then((busca) => res.json(busca))
        .catch(erro => console.log("erro busca" + erro))
})

//PESQUISA COM GET
app.get("/busca/:nome", (req, res) => {

    const { nome } = req.params

    //Verifica se a palavra buscada não é vazia
    if (!nome || !nome.trim()) {
        res.status(400).json("Busca inválida")
        return
    }

    itens.find({ nome: { $regex: nome.trim(), $options: "i" } }) //Regx faz busca parcial de palavras, e o i ignora maiuscula e minuscula
        .then((item) => {

            if (item.length > 0) { res.json(item) }
            else {
                res.status(404).json("Não encontrado")
            }
        })
        .catch(() => res.status(500).json("erro"))//ERRO 500 significa que a requisição veio, mas o servidou falhou

})



//UPDATE
app.put("/perdidos/:id", autenticar, (req, res) => {
    itens.findByIdAndUpdate(req.params.id, req.body, { new: true })
        .then((atualizado) => res.json(atualizado))
        .catch(erro => console.log("erro busca" + erro))
})

//DELETE
app.delete("/perdidos/:id",autenticar, (req, res) => {
    itens.findByIdAndDelete(req.params.id, req.body, { new: true })
        .then((atualizado) => res.json(atualizado))
        .catch(erro => console.log("erro busca" + erro))
})

//CREATE ENVIA INFORMAÇÕES
app.post("/cadastro",autenticar, async (req, res) => {
    
    try{
        const qtd = await itens.countDocuments()
        if (qtd>=5) {return res.status(403).json({msg: "Limite de 10 itens"})}
        
        const novoCadastro = await itens.create(req.body)
        return res.status(201).json(novoCadastro)
    }

    catch (erro) {
        console.error("erro cadastro:", erro)
        return res.status(500).json({msg: "Erro no servidor"})
    }   
})

app.listen(3000, () => console.log("Servidor rodando 3000"))


//todos itens encontrados na tabela
//itens.find()

//percorre todos itens da tabela os exibe
//itens.find().toArray()

//Exibe todos os nomes da coleção - find primeiro parâmetro é condicional, sendo escolhe oque exibir
//itens.find({}, { projection: { nome: 1, _id: 0 } }).toArray()



