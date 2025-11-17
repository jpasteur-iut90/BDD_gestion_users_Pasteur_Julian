const pool = require('../database/db');

async function requireAuth(req, res, next) {
    const token = req.headers['authorization'];
    
    if (!token) {
        return res.status(401).json({ error: 'token manquant' });
    }

    const result = await pool.query(
        `SELECT s.utilisateur_id, u.email, u.nom, u.prenom 
         FROM sessions s 
         INNER JOIN utilisateurs u ON s.utilisateur_id = u.id 
         WHERE s.token = $1 
         AND s.actif = true 
         AND s.date_expiration > CURRENT_TIMESTAMP 
         AND u.actif = true`,
        [token]
    );

    if (result.rows.length === 0) {
        return res.status(401).json({ error: 'token invalide' });
    }

    req.user = result.rows[0];
    next();
}

function requirePermission(ressource, action) {
    return async (req, res, next) => {
        const result = await pool.query(
            'SELECT utilisateur_a_permission($1, $2, $3) AS a_permission',
            [req.user.utilisateur_id, ressource, action]
        );

        if (!result.rows[0].a_permission) {
            return res.status(403).json({ error: 'permission refusée' });
        }

        next();
    };
}

module.exports = { requireAuth, requirePermission };