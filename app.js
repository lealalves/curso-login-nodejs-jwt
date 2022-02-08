require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// config json response
app.use(express.json())

// modulos
const User = require('./models/User')

// private route
app.get('/user/:id', checkToken, async(req, res) => {
    const id = req.params.id

    // check user exists
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(404).json({message: "Usuário não encontrado"})
    }

    res.status(200).json({ user })

})

function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if(!token){
        return res.status(401).json({message: "acesso negado"})
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch (error) {
        res.status(400).json({message: "Token Inválido"})
    }
    
}

// open route - public route
app.get('/', (req,res) => {
    res.status(200).json({message: "deu certo!"})
})


// register user
app.post('/auth/register', async(req,res) => {

    const {name, email, password, confirmpassword} = req.body

    //validation
    if(!name){
        return res.status(422).json({message: 'o nome é obrigatório!'})
    }
    if(!email){
        return res.status(422).json({message: 'o email é obrigatório!'})
    }
    if(!password){
        return res.status(422).json({message: 'a senha é obrigatória!'})
    }
    if(password !== confirmpassword){
        return res.status(422).json({message: 'as senhas não conferem!'})
    }


    // check if user exists
    const userExists = await User.findOne({email: email})

    if(userExists) {
        return res.status(422).json({message: 'email ja registrado!'})
    }

    // create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // create user
    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {

        await user.save()

        res.status(201).json({message: 'Usuário criado com sucesso!'})
        
    } catch (error) {
        console.log(error);
        res.status(500).json({message: 'Aconteceu algum erro no servidor, por favor tente novamente mais tarde!'})

    }
})


// login user
app.post('/auth/login', async(req, res) => {
    const {email, password} = req.body

    // validacao
    if(!email){
        return res.status(422).json({message: 'o email é obrigatório!'})
    }
    if(!password){
        return res.status(422).json({message: 'a senha é obrigatória!'})
    }

    // check user exists
    const user = await User.findOne({email: email})

    if(!user) {
        return res.status(422).json({message: 'Usuário nao encontrado!'})
    }

    // check if password match
    const checkPassword = await bcrypt.compare(password, user.password)

    if(!checkPassword){
        return res.status(422).json({message: 'Senha inválida!'})
    }


    try {

        const secret = process.env.SECRET

        const token = jwt.sign({
            id: user._id,
            },
            secret
        )

        res.status(200).json({message: 'Autenticação realizada com sucesso!', token})
            
        
    } catch (error) {
        console.log(error);
        res.status(500).json({message: 'Aconteceu algum erro no servidor, por favor tente novamente mais tarde!'})
    }

})

// credenciais db
const dbUser = process.env.DB_USER
const dbPass = process.env.DB_PASSWORD

mongoose.connect(`mongodb+srv://${dbUser}:${dbPass}@cluster0.tjbop.mongodb.net/myFirstDatabase?retryWrites=true&w=majority`).then(() =>{
    app.listen(3000)
    console.log('Conectou ao Banco!');

}).catch((err) => {
    console.log(err);
})

