//import Usuario from './Usuario.js'

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

//todos itens encontrados na tabela
//itens.find()

//percorre todos itens da tabela os exibe
//itens.find().toArray()

//Exibe todos os nomes da coleção - find primeiro parâmetro é condicional, sendo escolhe oque exibir
//itens.find({}, { projection: { nome: 1, _id: 0 } }).toArray()