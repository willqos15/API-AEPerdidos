import mongoose from "mongoose"

//modelo de cadastro para novos itens - Schema define a estrutura do documento da coleção. String, Number, Boolean, Date
const itemnovoSchema = new mongoose.Schema({
  nome: String, 
  descricao: String, 
  local: String, 
  proprietario: String, 
  contato: String, 
  encontrado: Boolean, 
  foto: String,
}
)

export default mongoose.model('itens', itemnovoSchema)