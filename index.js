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


dotenv.config() //procura o arquivo env de configuração

//Importa Scheema de cadastro post
import itens from "./itemnovo.js"

//instancia express na variavel app
const app = express()
app.use(cors({
    origin: "https://achados-e-perdidos-gray.vercel.app"
    //origin: "http://localhost:5173"
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




function autenticar(req, res, next) {

    const tokenheader = req.headers["authorization"]
    if (!tokenheader) return res.status(401).json({ msg: "erro" })

    const token = tokenheader.split(' ')[1] //quebra a string e pega o segundo elemento
    if (!token) return res.status(401).json({ msg: "erro" })

    try {
        req.user = jwt.verify(token, process.env.jwtsecret)
        next()
    } catch {
        return res.status(401).json({ msg: 'erro' })
    }

}

//verifica se usuário está logado
app.get('/testelogin', autenticar, (req, res) => {
    res.status(200).json({ logado: true, nivel: req.user.nivel })
})

//sair da conta
app.post('/logout', (req, res) => {
    res.status(200).json({ msg: "logout realizado com sucesso" })
})

//faz o login completo
app.post('/testelogin', async (req, res) => {
    const { email, password } = req.body
    if (!email || !password) { return res.status(422).json({ msg: 'Email e senha obrigatórios' }) }
    if (email === process.env.testelogin) {

        const comparasenha = await bcrypt.compare(password, process.env.testesenha)

        if (!comparasenha) { return res.status(401).json({ msg: 'SENHA INCORRETA' }) }

        const meutoken = jwt.sign( //sign cria um token (payload, secret, options)
            { nivel: "admin" }, process.env.jwtsecret, { expiresIn: "15m" })

        res.status(200).json({ msg: "LOGIN COM SUCESSO", token: meutoken })

    } else { return res.status(400).json({ msg: 'LOGIN INCORRETO' }) }
})

//const senhahash = await bcrypt.hash("",12)
//console.log(senhahash)

app.post('/atualizatoken', (req, res) => {

    const authHeader = req.headers["authorization"]
    if (!authHeader) return res.status(401).json({ msg: "ERRO" })

    const token = authHeader.split(' ')[1]
    if (!token) return res.status(401).json({ msg: "ERRO" })

    try {
        const dadostoken = jwt.verify(token, process.env.jwtsecret)
        const novotoken = jwt.sign(
            { nivel: dadostoken.nivel }, process.env.jwtsecret, { expiresIn: "15m" })

        res.status(200).json({ msg: 'okay', token: novotoken })

    } catch { res.status(401).json({ msg: 'erro' }) }



})



//UPLOAD DE IMAGEM
const upload = multer({ storage: multer.memoryStorage() }) //deixa o arquivo na RAM temporariamente
app.post('/upload', autenticar, upload.single('file'), (req, res) => { //o input no html tem que ter name='file'



    if (!req.file) {
        return res.status(400).json({ erro: "Sem arquivo" })
    }


    cloudinary.uploader.upload_stream( //permite pegar da RAM

        (erro, resultado) => {
            if (erro) return res.status(500).json(erro)
            return res.json({
                url: resultado.secure_url,
                public_idfoto: resultado.public_id
            })
        }

    ).end(req.file.buffer)
})


//DELETAR IMAGEM
app.delete('/imgdel/:public_id',
    (req, res) => {

        const { public_id } = req.params

        if (!public_id) {
            return res.status(400).json({ msg: "Id publico não informado" })
        }

        cloudinary.uploader.destroy(public_id)
            .then((resultado) => {

                if (resultado.result !== 'ok') {
                    return res.status(404).json({ msg: "imagem não encontrada" })
                }
                res.status(200).json({ msg: "sucesso ao deletar imagem" })
            })
            .catch((erro) => res.status(500).json({ msg: `falha ao apagar imagem` }))

    }
)



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
app.put("/perdidos/:id", autenticar, async (req, res) => {

    try {
        const item = await itens.findById(req.params.id)

        if (!item) { return res.status(404).json({ msg: "item não encontrado " }) }

        const Idfoto = item.public_idfoto
        await cloudinary.uploader.destroy(Idfoto)

        await itens.findByIdAndUpdate(req.params.id, req.body, { new: true })
        return res.status(200).json({ msg: "itens atualizados com sucesso" })
    }

    catch (erro) {return res.status(500).json({ msg: "erro ao atualizar" })}
})



//DELETE
app.delete("/perdidos/:id", autenticar, async (req, res) => {

    try {
        //busca o item primeiro para pegar o publicidfoto
        const item = await itens.findById(req.params.id)

        if (!item) { return res.status(404).json({ msg: "item não encontrado " }) }

        const Idfoto = item.public_idfoto

        await itens.findByIdAndDelete(req.params.id)

        if (Idfoto) {
            await cloudinary.uploader.destroy(Idfoto)
        }

        return res.status(200).json({ msg: "img e item deletados com sucesso" })
    }

    catch (erro) {
        return res.status(500).json({ msg: "erro no servidor" })
    }
})


//CREATE ENVIA INFORMAÇÕES
app.post("/cadastro", autenticar, async (req, res) => {

    try {
        const qtd = await itens.countDocuments()
        if (qtd >= 5) { return res.status(403).json({ msg: "Limite de 5 itens" }) }

        const novoCadastro = await itens.create(req.body)
        return res.status(201).json(novoCadastro)
    }

    catch (erro) {
        console.error("erro cadastro:", erro)
        return res.status(500).json({ msg: "Erro no servidor" })
    }
})

app.listen(3000, () => console.log("Servidor rodando 3000"))

