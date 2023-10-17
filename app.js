require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");

const app = express();

// Config para o node aceitar JSON
app.use(express.json());

// Model pra usar na criação e busca de usuarios
const User = require("./model/User");

// Middlware pra verificar o token jwt no login do usuario
function checkToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ msg: "Acesso negado!" });
  }
  try {
    const secret = process.env.secret;
    jwt.verify(token, secret);
    next();
  } catch (err) {
    res.status(400).json({ msg: "Token inválido!" });
  }
}

// Rota publica
app.get("/", (req, res) => {
  return res.status(200).json({ msg: "Tudo certo" });
});

// Rota privada para usuarios de token
app.get("/user/:id", checkToken, async (req, res) => {
  const id = req.params.id;
  // Checando se o usuário existe
  const user = await User.findById(id, "-password");
  if (!user) {
    return res.status(404).json({ msg: "Usuário não encontrado" });
  }
  res.status(200).json({ user });
});

// Rota de Registro de novos Usuários
app.post("/auth/register", async (req, res) => {
  const { name, email, password, confirmpassword } = req.body;

  // Validações de campos da requisição
  if (!name) {
    return res.status(422).json({ msg: "O nome é obrigatório!" });
  }
  if (!email) {
    return res.status(422).json({ msg: "O e-mail é obrigatório!" });
  }
  if (!password) {
    return res.status(422).json({ msg: "O password é obrigatório!" });
  }
  if (password != confirmpassword) {
    return res.status(422).json({ msg: "A senhas não conferem " });
  }

  // Checando se esse novo usuário existe
  const userExists = await User.findOne({ email: email });
  if (userExists) {
    return res.status(422).json({ msg: "Por Favor, Utilize outro e-mail" });
  }

  // Criando a senha com hash usando o bcrypt
  const salt = await bcrypt.genSalt(12);
  const passwordHash = await bcrypt.hash(password, salt);

  // Criando o Usuario
  const user = new User({
    name,
    email,
    password: passwordHash,
  });
  try {
    await user.save();
    res.status(201).json({ msg: "Usuário criado com Sucesso" });
  } catch (err) {
    console.log(err);
    res.status(500).json({
      msg: "Infelizmente aconteceu algum erro no servidor, tente novamente mais tarde",
    });
  }
});

// Rota pra login
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body;
  // Validações
  if (!email) {
    return res.status(422).json({ msg: "O e-mail é obrigatório!" });
  }
  if (!password) {
    return res.status(422).json({ msg: "O password é obrigatório!" });
  }

  // Checando se o usuário existe no banco de dados
  const user = await User.findOne({ email: email });
  if (!user) {
    return res.status(422).json({ msg: "Usuário não encontrado" });
  }

  // Checando se a senha que o usuario informou é a senha correta

  const checkPassword = await bcrypt.compare(password, user.password);

  if (!checkPassword) {
    return res.status(422).json({ msg: "Senha inválida" });
  }

  try {
    const secret = process.env.secret;
    const token = jwt.sign(
      {
        id: user._id,
      },
      secret
    );
    res.status(200).json({
      msg: `Autenticação realizada com sucesso`,
      token: token,
    });
  } catch (err) {
    console.log(err);
    res.status(500).json({ msg: "Aconteceu um erro no servidor" });
  }
});

// Credenciais pra acessar o banco de dados
// Conectando ao banco de dados
const dbUser = process.env.DB_USER;
const dbPassword = process.env.DB_PASSWORD;

mongoose
  .connect(
    `mongodb+srv://${dbUser}:${dbPassword}@cluster0.rgy1phc.mongodb.net/your-database-name?retryWrites=true&w=majority`
  )
  .then(() => {
    app.listen(5000);
    console.log("Conectou ao banco de dados");
  })
  .catch((err) => console.log(err));
