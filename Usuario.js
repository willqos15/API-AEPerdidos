import mongoose from "mongoose"

const UsuarioSchema = new mongoose.Schema({
    name: String,
    email: String,
    password: String
})

export default mongoose.model('Usuario', UsuarioSchema)