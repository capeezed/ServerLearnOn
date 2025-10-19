require('dotenv').config();
const axios = require('axios');

async function testEmail() {
    try {
        const res = await axios.post(
            'https://api.brevo.com/v3/smtp/email',
            {
                sender: { email: process.env.EMAIL_SERVICE_USER },
                to: [{ email: 'seuemailteste@gmail.com' }],
                subject: 'Teste Brevo no Render',
                htmlContent: '<p>Testando envio via API Brevo</p>'
            },
            {
                headers: {
                    'api-key': process.env.EMAIL_SERVICE_PASS,
                    'Content-Type': 'application/json'
                }
            }
        );
        console.log('✅ Sucesso:', res.data);
    } catch (err) {
        console.error('❌ Erro:', err.response?.data || err.message);
    }
}

testEmail();
