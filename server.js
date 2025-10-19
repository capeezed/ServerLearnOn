// server.js

require('dotenv').config(); // LER VARIÁVEIS DE AMBIENTE PRIMEIRO

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const db = require('./db'); // Importa o pool de conexões do MySQL
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const crypto = require('crypto');

const app = express();
const PORT = process.env.SERVER_PORT || 3000;
const SALT_ROUNDS = 10; // Fator de segurança para Bcrypt

// ------------------------------------
// MIDDLEWARES GERAIS
// ------------------------------------

// ✅ Permite que o Express leia JSON do corpo da requisição
app.use(express.json());

// ✅ Configuração robusta de CORS (funciona no Render + Netlify)
const allowedOrigins = [
  "https://learnonstartup.netlify.app", // seu front-end hospedado
  "http://localhost:4200" // para desenvolvimento local
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      console.warn("❌ CORS bloqueado para origem:", origin);
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE", "PATCH"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

// ------------------------------------
// CONFIGURAÇÃO DO TRANSPORTE DE EMAIL
// ------------------------------------
const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_SERVICE_HOST,
  port: process.env.EMAIL_SERVICE_PORT,
  secure: false,
  auth: {
    user: process.env.EMAIL_SERVICE_USER,
    pass: process.env.EMAIL_SERVICE_PASS,
  },
});

// Função opcional para testar conexão SMTP
async function verifyTransporter() {
  try {
    await transporter.verify();
    console.log("✅ SMTP: Nodemailer pronto para enviar e-mails!");
  } catch (error) {
    console.error("❌ SMTP ERRO CRÍTICO:", error);
  }
}
verifyTransporter();

// ------------------------------------
// ROTAS DE AUTENTICAÇÃO
// ------------------------------------

// Teste de rota básica
app.get('/api/auth/test', (req, res) => {
  res.status(200).json({ message: 'Rotas de Auth estão funcionando!' });
});

// 🔑 ROTA: Esqueci a Senha (gera token e envia e-mail)
app.post('/api/auth/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    const [rows] = await db.query('SELECT id FROM usuarios WHERE email = ?', [email]);
    const user = rows[0];

    // Resposta genérica para segurança
    if (!user) {
      return res.status(200).json({ message: "Se o e-mail estiver cadastrado, você receberá um link." });
    }

    const resetToken = crypto.randomBytes(32).toString('hex');
    const expires = new Date(Date.now() + 3600000); // 1 hora

    await db.query(
      'UPDATE usuarios SET reset_token = ?, reset_token_expires = ? WHERE id = ?',
      [resetToken, expires, user.id]
    );

    const resetUrl = `${process.env.FRONTEND_URL}/redefinir-senha/${resetToken}`;

    const mailOptions = {
      to: email,
      from: process.env.EMAIL_SERVICE_USER,
      subject: 'LearnOn - Redefinição de Senha',
      html: `
        <p>Você solicitou a redefinição de senha.</p>
        <p>Clique neste link para redefinir sua senha: 
          <a href="${resetUrl}">${resetUrl}</a>
        </p>
        <p>O link expirará em 1 hora.</p>
      `,
    };

    await transporter.sendMail(mailOptions);
    res.status(200).json({ message: 'Email de redefinição de senha enviado.' });

  } catch (error) {
    console.error('❌ Erro ao solicitar redefinição de senha:', error);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

// 📝 ROTA: Registro de Usuário
app.post('/api/auth/register', async (req, res) => {
  const { nome, email, senha } = req.body;

  if (!nome || !email || !senha) {
    return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
  }

  try {
    const senhaHash = await bcrypt.hash(senha, SALT_ROUNDS);
    const query = `
      INSERT INTO usuarios (nome, email, senha_hash, tipo_usuario) 
      VALUES (?, ?, ?, 'aluno')
    `;
    const [result] = await db.query(query, [nome, email, senhaHash]);

    res.status(201).json({
      message: 'Usuário registrado com sucesso!',
      userId: result.insertId
    });

  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Este email já está cadastrado.' });
    }
    console.error('❌ Erro no registro:', error);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

// 🔐 ROTA: Login
app.post('/api/auth/login', async (req, res) => {
  const { email, senha } = req.body;

  if (!email || !senha) {
    return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
  }

  try {
    const query = `SELECT id, nome, senha_hash, tipo_usuario FROM usuarios WHERE email = ?`;
    const [rows] = await db.query(query, [email]);
    const user = rows[0];

    if (!user) {
      return res.status(401).json({ message: 'Credenciais inválidas.' });
    }

    const isMatch = await bcrypt.compare(senha, user.senha_hash);

    if (!isMatch) {
      return res.status(401).json({ message: 'Credenciais inválidas.' });
    }

    const token = jwt.sign(
      {
        userId: user.id,
        email: user.email,
        type: user.tipo_usuario
      },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    res.status(200).json({
      message: 'Login bem-sucedido!',
      token: token,
      user: {
        id: user.id,
        nome: user.nome,
        tipo: user.tipo_usuario
      }
    });

  } catch (error) {
    console.error('❌ Erro no login:', error);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

// 🔄 ROTA: Resetar Senha
app.post('/api/auth/reset-password', async (req, res) => {
  const { token, novaSenha } = req.body;

  if (!token || !novaSenha) {
    return res.status(400).json({ message: 'Token e nova senha são obrigatórios.' });
  }

  try {
    const [rows] = await db.query(
      `SELECT id FROM usuarios 
       WHERE reset_token = ? 
       AND reset_token_expires > NOW()`,
      [token]
    );

    const user = rows[0];
    if (!user) {
      return res.status(400).json({ message: "Token inválido ou expirado." });
    }

    const novaSenhaHash = await bcrypt.hash(novaSenha, SALT_ROUNDS);

    await db.query(
      `UPDATE usuarios 
       SET senha_hash = ?, 
           reset_token = NULL, 
           reset_token_expires = NULL 
       WHERE id = ?`,
      [novaSenhaHash, user.id]
    );

    res.status(200).json({ message: "Senha redefinida com sucesso." });

  } catch (error) {
    console.error('❌ Erro ao redefinir senha:', error);
    res.status(500).json({ message: 'Erro interno no servidor.' });
  }
});

// ------------------------------------
// INICIALIZAÇÃO DO SERVIDOR
// ------------------------------------
app.listen(PORT, () => {
  console.log(`🚀 Servidor rodando na porta ${PORT}`);
});
