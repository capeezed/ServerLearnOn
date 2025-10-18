// db.js

require('dotenv').config();
const mysql = require('mysql2/promise');

// Configuração de conexão usando variáveis de ambiente
const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT
};

// Cria um pool de conexões para gerenciar múltiplas requisições
const pool = mysql.createPool(dbConfig);

// Função para testar a conexão (opcional, mas útil)
async function testConnection() {
    try {
        const connection = await pool.getConnection();
        console.log("Conectado ao MySQL com sucesso!");
        connection.release(); // Libera a conexão
    } catch (error) {
        console.error("Erro ao conectar ao MySQL:", error);
        // Sugestão: sair do processo se a conexão inicial falhar
        process.exit(1); 
    }
}

testConnection();

module.exports = pool;