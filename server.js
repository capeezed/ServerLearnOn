// server.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const db = require('./db'); // Importa o pool de conexões do MySQL

const app = express();
const PORT = process.env.SERVER_PORT || 3000;
const SALT_ROUNDS = 10; // Fator de segurança para Bcrypt
const jwt = require('jsonwebtoken');

// ------------------------------------
// MIDDLEWARE
// ------------------------------------

// Permite o parseamento de JSON nas requisições (req.body)
app.use(express.json());

// Configura o CORS: permite que o frontend Angular (localhost:4200) se conecte
app.use(cors({
    origin: 'http://localhost:4200',
    methods: ['GET', 'POST', 'PUT', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));


// ------------------------------------
// ROTAS DE AUTENTICAÇÃO (AUTH)
// ------------------------------------

// ROTA DE REGISTRO (Cadastro de Usuário)
app.post('/api/auth/register', async (req, res) => {
    const { nome, email, senha } = req.body;
    
    // Validação básica do lado do servidor
    if (!nome || !email || !senha) {
        return res.status(400).json({ message: 'Todos os campos são obrigatórios.' });
    }

    try {
        // 1. Criptografa a senha antes de qualquer coisa
        const senhaHash = await bcrypt.hash(senha, SALT_ROUNDS);

        // 2. Insere o novo usuário no MySQL
        const query = `
            INSERT INTO usuarios (nome, email, senha_hash, tipo_usuario) 
            VALUES (?, ?, ?, 'aluno')
        `;
        // tipo_usuario é definido como 'aluno' por padrão
        const [result] = await db.query(query, [nome, email, senhaHash]);

        // 3. Resposta de sucesso
        res.status(201).json({ 
            message: 'Usuário registrado com sucesso!',
            userId: result.insertId 
        });

    } catch (error) {
        // 4. Tratamento de erro (ex: email já existe)
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Este email já está cadastrado.' });
        }
        console.error('Erro no registro:', error);
        res.status(500).json({ message: 'Erro interno no servidor.' });
    }
});

app.post('/api/auth/login', async (req, res) => {
    const { email, senha } = req.body;

    if (!email || !senha) {
        return res.status(400).json({ message: 'Email e senha são obrigatórios.' });
    }

    try {
        // 1. Buscar o usuário no MySQL
        const query = `SELECT id, nome, senha_hash, tipo_usuario FROM usuarios WHERE email = ?`;
        const [rows] = await db.query(query, [email]);
        const user = rows[0];

        // 2. Verificar se o usuário existe
        if (!user) {
            // É uma boa prática usar uma mensagem genérica para não revelar se o email existe
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }

        // 3. Comparar a senha fornecida com o hash salvo (Bcrypt)
        const isMatch = await bcrypt.compare(senha, user.senha_hash);

        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciais inválidas.' });
        }

        // 4. Gerar o Token JWT (Autenticação bem-sucedida)
        const token = jwt.sign(
            { 
                userId: user.id, 
                email: user.email,
                type: user.tipo_usuario
            },
            process.env.JWT_SECRET,
            { expiresIn: '1h' } // O token expira em 1 hora
        );

        // 5. Resposta de sucesso: Envia o token e informações básicas do usuário
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
        console.error('Erro no login:', error);
        res.status(500).json({ message: 'Erro interno no servidor.' });
    }
});

// ------------------------------------
// INICIALIZAÇÃO DO SERVIDOR
// ------------------------------------

app.listen(PORT, () => {
    console.log(`Servidor rodando na porta http://localhost:${PORT}`);
});