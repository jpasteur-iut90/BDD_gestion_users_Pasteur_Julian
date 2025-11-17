const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const bcrypt = require('bcrypt');
const { v4: uuidv4 } = require('uuid');
const { requireAuth } = require('../middleware/auth');

// inscription
router.post('/register', async (req, res) => {
    const { email, password, nom, prenom } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'email et password requis' });
    }

    const client = await pool.connect();
    await client.query('BEGIN');

    const checkUser = await client.query(
        'SELECT id FROM utilisateurs WHERE email = $1',
        [email]
    );

    if (checkUser.rows.length > 0) {
        await client.query('ROLLBACK');
        client.release();
        return res.status(409).json({ error: 'email deja utilisé' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await client.query(
        `INSERT INTO utilisateurs (email, password_hash, nom, prenom) 
         VALUES ($1, $2, $3, $4) 
         RETURNING id, email, nom, prenom`,
        [email, passwordHash, nom, prenom]
    );

    await client.query(
        `INSERT INTO utilisateur_roles (utilisateur_id, role_id) 
         SELECT $1, id FROM roles WHERE nom = 'user'`,
        [result.rows[0].id]
    );

    await client.query('COMMIT');
    client.release();

    res.status(201).json(result.rows[0]);
});

// connexion
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'email et password requis' });
    }

    const result = await pool.query(
        `SELECT id, email, password_hash, nom, prenom, actif 
         FROM utilisateurs WHERE email = $1`,
        [email]
    );

    if (result.rows.length === 0) {
        return res.status(401).json({ error: 'identifiants incorrects' });
    }

    const user = result.rows[0];

    if (!user.actif || !await bcrypt.compare(password, user.password_hash)) {
        return res.status(401).json({ error: 'identifiants incorrects' });
    }

    const token = uuidv4();
    const expiresAt = new Date();
    expiresAt.setHours(expiresAt.getHours() + 24);

    await pool.query(
        `INSERT INTO sessions (utilisateur_id, token, date_expiration) 
         VALUES ($1, $2, $3)`,
        [user.id, token, expiresAt]
    );

    res.json({
        token: token,
        user: {
            id: user.id,
            email: user.email,
            nom: user.nom,
            prenom: user.prenom
        }
    });
});

// profil
router.get('/profile', requireAuth, async (req, res) => {
    const result = await pool.query(
        `SELECT u.id, u.email, u.nom, u.prenom, u.actif,
                array_agg(r.nom) FILTER (WHERE r.nom IS NOT NULL) AS roles
         FROM utilisateurs u
         LEFT JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
         LEFT JOIN roles r ON ur.role_id = r.id
         WHERE u.id = $1
         GROUP BY u.id`,
        [req.user.utilisateur_id]
    );

    res.json(result.rows[0]);
});

// deconnexion
router.post('/logout', requireAuth, async (req, res) => {
    await pool.query(
        'UPDATE sessions SET actif = false WHERE token = $1',
        [req.headers['authorization']]
    );

    res.json({ message: 'deconnexion ok' });
});

module.exports = router;