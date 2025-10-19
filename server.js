// server.js
require('dotenv').config(); // 🔹 Lê variáveis de ambiente primeiro

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const db = require('./db');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
// const nodemailer = require('nodemailer'); // ❌ REMOVIDO: Não usa mais Nodemailer/Mailtrap
const axios = require('axios'); // 📦 NOVO: Adiciona Axios para a API Brevo

const app = express();
const PORT = process.env.SERVER_PORT || 3000;
const SALT_ROUNDS = 10;

// ------------------------------------
// 🧩 MIDDLEWARES
// ------------------------------------

const allowedOrigins = [
    'https://learnonstartup.netlify.app',
    'http://localhost:4200',
    'https://serverlearnon.onrender.com'
];

app.use(cors({
    origin: (origin, callback) => {
        if (!origin) return callback(null, true);
        
        if (allowedOrigins.indexOf(origin) !== -1) {
            callback(null, true);
        } else {
            console.warn(`🌐 CORS Blocked: Origin ${origin} not allowed.`);
            callback(new Error('Not allowed by CORS'));
        }
    },
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true
}));
app.use(express.json());

// ------------------------------------
// ✉️ FUNÇÃO DE ENVIO DE EMAIL (Brevo API)
// ------------------------------------
// 🚨 AQUI ESTÁ A MUDANÇA: Usando AXIOS para a API HTTP da Brevo
async function sendEmail(to, subject, htmlContent) {
    try {
        const response = await axios.post(
            'https://api.brevo.com/v3/smtp/email',
            {
                // EMAIL_SERVICE_USER deve ser um remetente validado na Brevo
                sender: { email: process.env.EMAIL_SERVICE_USER }, 
                to: [{ email: to }],
                subject: subject,
                htmlContent: htmlContent
            },
            {
                headers: {
                    // EMAIL_SERVICE_PASS DEVE ser a API Key da Brevo
                    'api-key': process.env.EMAIL_SERVICE_PASS, 
                    'Content-Type': 'application/json'
                },
                timeout: 10000 // ⏱ Timeout de 10s
            }
        );
        console.log(`✅ E-mail enviado para ${to} via Brevo.`);
        return response.data;
    } catch (err) {
        if (err.response?.status === 401) {
            console.error('❌ Erro 401: API Key Brevo inválida ou mal configurada');
            throw new Error('API Key inválida');
        }
        console.error(`❌ Erro FATAL ao enviar e-mail para ${to}:`, err.response?.data || err.message);
        throw err;
    }
}


// ------------------------------------
// 🔑 ROTAS DE AUTENTICAÇÃO
// ------------------------------------

// Teste simples
app.get('/api/auth/test', (req, res) => {
    res.status(200).json({ message: 'Rotas de Auth funcionando corretamente ✅' });
});

// Esqueci a senha
app.post('/api/auth/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const [rows] = await db.query('SELECT id FROM usuarios WHERE email = ?', [email]);
        const user = rows[0];

        if (!user) {
            return res.status(200).json({ message: 'Se o e-mail estiver cadastrado, você receberá um link.' });
        }

        const resetToken = crypto.randomBytes(32).toString('hex');
        const expires = new Date(Date.now() + 3600000); // 1 hora

        await db.query(
            'UPDATE usuarios SET reset_token = ?, reset_token_expires = ? WHERE id = ?',
            [resetToken, expires, user.id]
        );

        const resetUrl = `${process.env.FRONTEND_URL}/redefinir-senha/${resetToken}`;

        const htmlContent = `
            <p>Você solicitou a redefinição de senha.</p>
            <p>Clique neste link para redefinir sua senha: <a href="${resetUrl}">${resetUrl}</a></p>
            <p>O link expirará em 1 hora.</p>
        `;

        await sendEmail(email, 'LearnOn - Redefinição de Senha', htmlContent);

        res.status(200).json({ message: 'Email de redefinição de senha enviado.' });

    } catch (error) {
        console.error('Erro ao solicitar redefinição de senha:', error.message);
        res.status(500).json({ message: 'Erro ao processar a solicitação. Tente novamente.' }); 
    }
});

// Registro
app.post('/api/auth/register', async (req, res) => {
    const { nome, email, senha } = req.body;
    if (!nome || !email || !senha) return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });

    try {
        const senhaHash = await bcrypt.hash(senha, SALT_ROUNDS);
        const query = `INSERT INTO usuarios (nome, email, senha_hash, tipo_usuario) VALUES (?, ?, ?, 'aluno')`;
        const [result] = await db.query(query, [nome, email, senhaHash]);

        res.status(201).json({ message: 'Usuário registrado com sucesso!', userId: result.insertId });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') return res.status(409).json({ message: 'Este email já está cadastrado.' });
        console.error('Erro no registro:', error.message);
        res.status(500).json({ message: 'Erro interno no servidor.' });
    }
});

// Login
app.post('/api/auth/login', async (req, res) => {
    const { email, senha } = req.body;
    if (!email || !senha) return res.status(400).json({ message: 'Email e senha são obrigatórios.' });

    try {
        const [rows] = await db.query(`SELECT id, nome, senha_hash, tipo_usuario FROM usuarios WHERE email = ?`, [email]);
        const user = rows[0];

        if (!user) return res.status(401).json({ message: 'Credenciais inválidas.' });

        const isMatch = await bcrypt.compare(senha, user.senha_hash);
        if (!isMatch) return res.status(401).json({ message: 'Credenciais inválidas.' });

        const token = jwt.sign(
            { userId: user.id, email: user.email, type: user.tipo_usuario },
            process.env.JWT_SECRET,
            { expiresIn: '1h' }
        );

        res.status(200).json({
            message: 'Login bem-sucedido!',
            token,
            user: { id: user.id, nome: user.nome, tipo: user.tipo_usuario },
        });

    } catch (error) {
        console.error('Erro no login:', error.message);
        res.status(500).json({ message: 'Erro interno no servidor.' });
    }
});

// Resetar senha
app.post('/api/auth/reset-password', async (req, res) => {
    const { token, novaSenha } = req.body;
    if (!token || !novaSenha) return res.status(400).json({ message: 'Token e nova senha são obrigatórios.' });

    try {
        const [rows] = await db.query(
            `SELECT id FROM usuarios WHERE reset_token = ? AND reset_token_expires > NOW()`,
            [token]
        );

        const user = rows[0];
        if (!user) return res.status(400).json({ message: 'Token inválido ou expirado.' });

        const novaSenhaHash = await bcrypt.hash(novaSenha, SALT_ROUNDS);

        await db.query(
            `UPDATE usuarios SET senha_hash = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?`,
            [novaSenhaHash, user.id]
        );

        res.status(200).json({ message: 'Senha redefinida com sucesso.' });
    } catch (error) {
        console.error('Erro ao redefinir senha:', error.message);
        res.status(500).json({ message: 'Erro interno no servidor.' });
    }
});

// ------------------------------------
// 🚀 INICIAR SERVIDOR
// ------------------------------------
app.listen(PORT, () => {
    console.log(`✅ Servidor rodando na porta ${PORT}`);
    console.log(`🌐 CORS habilitado para: https://learnonstartup.netlify.app`);
});