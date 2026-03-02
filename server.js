
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();

// CORS 
app.use(
  cors({
    origin: '*', 
  }),
);

app.use(express.json());

// Pool de conexão com MySQL
const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0,
  });
  
  // Teste de conexão ao iniciar
  async function testDbConnection() {
    try {
      const connection = await pool.getConnection();
      console.log('Conectado ao MySQL com sucesso!');
      connection.release();
    } catch (err) {
      console.error(' Erro ao conectar ao MySQL:', err.message);
      process.exit(1);
    }
  }
  
  testDbConnection();

// Helpers
function generateJwt(user) {
  const payload = { id: user.id, nome: user.nome, tipo: user.tipo };
  return jwt.sign(payload, process.env.JWT_SECRET || 'changeme', {
    expiresIn: '7d',
  });
}

async function findUserByEmail(email) {
  const [rows] = await pool.query('SELECT * FROM users WHERE email = ?', [email]);
  return rows[0] || null;
}



// Registro
app.post('/api/auth/register', async (req, res) => {
  try {
    const { nome, email, senha, tipo } = req.body;

    if (!nome || !email || !senha) {
      return res
        .status(400)
        .json({ message: 'Nome, email e senha são obrigatórios.' });
    }

    const existing = await findUserByEmail(email);
    if (existing) {
      return res.status(409).json({ message: 'Email já cadastrado.' });
    }

    const hashed = await bcrypt.hash(senha, 10);
    const userTipo = tipo || 'aluno';
    const status = 'ativo';

    const [result] = await pool.query(
      'INSERT INTO users (nome, email, senha_hash, tipo_usuario, status) VALUES (?, ?, ?, ?, ?)',
      [nome, email, hashed, userTipo, status],
    );

    const newUser = {
      id: result.insertId,
      nome,
      email,
      tipo: userTipo,
      status,
    };

    const token = generateJwt(newUser);

    return res.status(201).json({
      token,
      user: { id: newUser.id, nome: newUser.nome, tipo: newUser.tipo },
    });
  } catch (err) {
    console.error('Erro em /api/auth/register:', err);
    return res.status(500).json({ message: 'Erro no servidor.' });
  }
});

// Registro de professor 
app.post('/api/auth/register-professor', async (req, res) => {
  try {
    const { nome, email, senha } = req.body;

    if (!nome || !email || !senha) {
      return res
        .status(400)
        .json({ message: 'Nome, email e senha são obrigatórios.' });
    }

    const existing = await findUserByEmail(email);
    if (existing) {
      return res.status(409).json({ message: 'Email já cadastrado.' });
    }

    const hashed = await bcrypt.hash(senha, 10);
    const tipo = 'professor';
    const status = 'pendente';

    const [result] = await pool.query(
      'INSERT INTO users (nome, email, senha_hash, tipo_usuario, status) VALUES (?, ?, ?, ?, ?)',
      [nome, email, hashed, tipo, status],
    );

    return res.status(201).json({
      message:
        'Cadastro de professor realizado. Aguarde aprovação do administrador.',
      userId: result.insertId,
    });
  } catch (err) {
    console.error('Erro em /api/auth/register-professor:', err);
    return res.status(500).json({ message: 'Erro no servidor.' });
  }
});

// Login
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, senha } = req.body;

    if (!email || !senha) {
      return res
        .status(400)
        .json({ message: 'Email e senha são obrigatórios.' });
    }

    const user = await findUserByEmail(email);
    if (!user) {
      return res
        .status(401)
        .json({ message: 'Credenciais inválidas.' });
    }
    if (!user.senha_hash) {
      console.error('Usuário encontrado, mas coluna senha_hash está vazia ou inexistente para o email:', email);
      return res.status(500).json({ message: 'Erro nos dados de autenticação do usuário.' });
    }

    const senhaOk = await bcrypt.compare(senha, user.senha_hash);
    if (!senhaOk) {
      return res
        .status(401)
        .json({ message: 'Credenciais inválidas.' });
    }
    if (user.status === 'pendente') {
      return res
        .status(403)
        .json({ message: 'Sua conta está aguardando aprovação.' });
    }

    const token = generateJwt(user);
    return res.json({
      token,
      user: {
        id: user.id,
        nome: user.nome,
        tipo: user.tipo,
      },
    });
  } catch (err) {
    console.error('Erro em /api/auth/login:', err);
    return res.status(500).json({ message: 'Erro no servidor.' });
  }
});


app.post('/api/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res
        .status(400)
        .json({ message: 'Email é obrigatório.' });
    }

    const user = await findUserByEmail(email);
    if (!user) {
      return res.json({
        message:
          'Se o e-mail estiver cadastrado, você receberá um link de redefinição.',
      });
    }

    const token = crypto.randomBytes(32).toString('hex');
    const expHours = Number(process.env.RESET_TOKEN_EXP_HOURS || 1);
    const expiresAt = new Date(Date.now() + expHours * 60 * 60 * 1000);

    await pool.query(
      'INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)',
      [user.id, token, expiresAt],
    );

    console.log(
      `Token de reset para ${email}: ${token} (use na rota de reset do front)`,
    );

    return res.json({
      message:
        'Se o e-mail estiver cadastrado, você receberá um link de redefinição.',
    });
  } catch (err) {
    console.error('Erro em /api/auth/forgot-password:', err);
    return res.status(500).json({ message: 'Erro no servidor.' });
  }
});

// Reset de senha
app.post('/api/auth/reset-password', async (req, res) => {
  try {
    const { token, novaSenha } = req.body;

    if (!token || !novaSenha) {
      return res.status(400).json({
        message: 'Token e nova senha são obrigatórios.',
      });
    }

    const [rows] = await pool.query(
      'SELECT * FROM password_resets WHERE token = ?',
      [token],
    );
    const reset = rows[0];

    if (!reset) {
      return res
        .status(400)
        .json({ message: 'Token inválido.' });
    }

    const now = new Date();
    if (new Date(reset.expires_at) < now) {
      return res
        .status(400)
        .json({ message: 'Token expirado.' });
    }

    const hashed = await bcrypt.hash(novaSenha, 10);

    await pool.query('UPDATE users SET senha_hash = ? WHERE id = ?', [
      hashed,
      reset.user_id,
    ]);
    await pool.query(
      'UPDATE password_resets SET used_at = ? WHERE id = ?',
      [now, reset.id],
    );

    return res.json({
      message: 'Senha redefinida com sucesso!',
    });
  } catch (err) {
    console.error('Erro em /api/auth/reset-password:', err);
    return res.status(500).json({ message: 'Erro no servidor.' });
  }
});

// =============
// Pedidos
// =============

// Criar pedido
app.post('/api/pedidos/criar', async (req, res) => {
  try {
    const { duvida, solicitante_email } = req.body;

    if (!duvida) {
      return res
        .status(400)
        .json({ message: 'O campo "duvida" é obrigatório.' });
    }

    const [result] = await pool.query(
      'INSERT INTO pedidos (duvida, solicitante_email, status) VALUES (?, ?, ?)',
      [duvida, solicitante_email || null, 'pendente'],
    );

    return res.status(201).json({
      id: result.insertId,
      message: 'Pedido criado com sucesso.',
    });
  } catch (err) {
    console.error('Erro em /api/pedidos/criar:', err);
    return res.status(500).json({ message: 'Erro no servidor.' });
  }
});

// Listar pedidos pendentes (para o dashboard do professor)
app.get('/api/pedidos/pendentes', async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id,
              duvida,
              solicitante_email,
              created_at AS data_pedido
       FROM pedidos
       WHERE status = 'pendente'
       ORDER BY created_at DESC`,
    );

    return res.json(rows);
  } catch (err) {
    console.error('Erro em /api/pedidos/pendentes:', err);
    return res.status(500).json({ message: 'Erro no servidor.' });
  }
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`Servidor rodando em http://localhost:${port}`);
});
