const express = require('express');
const pool = require('./database/db');
const authRoutes = require('./routes/authRoutes');
const userRoutes = require('./routes/userRoutes');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

app.use('/api/auth', authRoutes);
app.use('/api/users', userRoutes);

app.get('/api/health', async (req, res) => {
    const result = await pool.query('SELECT NOW()');
    res.json({
        status: 'ok',
        database: 'connected',
        timestamp: result.rows[0].now
    });
});

app.listen(PORT, () => {
    console.log(`serveur sur http://localhost:${PORT}`);
});