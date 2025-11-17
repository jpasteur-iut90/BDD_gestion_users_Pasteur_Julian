const express = require('express');
const router = express.Router();
const pool = require('../database/db');
const { requireAuth, requirePermission } = require('../middleware/auth');

// liste users
router.get('/', requireAuth, requirePermission('users', 'read'), async (req, res) => {
    const limit = parseInt(req.query.limit) || 10;
    const offset = parseInt(req.query.page || 1) * limit - limit;

    const result = await pool.query(
        `SELECT u.id, u.email, u.nom, u.prenom, u.actif,
                array_agg(r.nom) FILTER (WHERE r.nom IS NOT NULL) AS roles
         FROM utilisateurs u
         LEFT JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
         LEFT JOIN roles r ON ur.role_id = r.id
         GROUP BY u.id
         ORDER BY u.id
         LIMIT $1 OFFSET $2`,
        [limit, offset]
    );

    res.json(result.rows);
});

// details utilisateur
router.get('/:id', requireAuth, requirePermission('users', 'read'), async (req, res) => {
    const result = await pool.query(
        `SELECT u.id, u.email, u.nom, u.prenom, u.actif,
                array_agg(r.nom) FILTER (WHERE r.nom IS NOT NULL) AS roles
         FROM utilisateurs u
         LEFT JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
         LEFT JOIN roles r ON ur.role_id = r.id
         WHERE u.id = $1
         GROUP BY u.id`,
        [req.params.id]
    );

    if (result.rows.length === 0) {
        return res.status(404).json({ error: 'utilisateur non trouvé' });
    }

    res.json(result.rows[0]);
});

// modifier utilisateur
router.put('/:id', requireAuth, requirePermission('users', 'write'), async (req, res) => {
    const { nom, prenom, actif } = req.body;

    const result = await pool.query(
        `UPDATE utilisateurs 
         SET nom = $1, prenom = $2, actif = $3, date_modification = CURRENT_TIMESTAMP 
         WHERE id = $4 
         RETURNING id, email, nom, prenom, actif`,
        [nom, prenom, actif, req.params.id]
    );

    if (result.rows.length === 0) {
        return res.status(404).json({ error: 'utilisateur introuvable' });
    }

    res.json(result.rows[0]);
});

// supprimer utilisateur
router.delete('/:id', requireAuth, requirePermission('users', 'delete'), async (req, res) => {
    if (parseInt(req.params.id) === req.user.utilisateur_id) {
        return res.status(400).json({ error: 'auto-suppression interdite' });
    }

    const result = await pool.query(
        'DELETE FROM utilisateurs WHERE id = $1 RETURNING id, email',
        [req.params.id]
    );

    if (result.rows.length === 0) {
        return res.status(404).json({ error: 'utilisateur non trouvé' });
    }

    res.json(result.rows[0]);
});

// permissions d'un utilisateur
router.get('/:id/permissions', requireAuth, async (req, res) => {
    const result = await pool.query(
        `SELECT DISTINCT p.nom, p.ressource, p.action
         FROM utilisateurs u
         INNER JOIN utilisateur_roles ur ON u.id = ur.utilisateur_id
         INNER JOIN role_permissions rp ON ur.role_id = rp.role_id
         INNER JOIN permissions p ON rp.permission_id = p.id
         WHERE u.id = $1`,
        [req.params.id]
    );

    res.json(result.rows);
});

module.exports = router;