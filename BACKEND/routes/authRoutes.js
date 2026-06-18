const express = require('express');
const router = express.Router();
const crypto = require('crypto'); // Module natif Node.js pour générer des tokens
const bcrypt = require('bcryptjs');
const User = require('../models/user');
const sendEmail = require('../utils/sendEmail');

// ─────────────────────────────────────────────
// POST /api/auth/forgot-password
// L'utilisateur envoie son email → on lui envoie un lien de réinitialisation
// ─────────────────────────────────────────────
router.post('/forgot-password', async (req, res) => {
  const { email } = req.body;

  try {
    // Cherche l'utilisateur par email
    const user = await User.findOne({ email });

    // Sécurité : on répond toujours la même chose pour ne pas révéler si l'email existe
    if (!user) {
      return res.status(200).json({ message: "Si cet email existe, un lien a été envoyé." });
    }

    // Génère un token aléatoire sécurisé (32 octets = 64 caractères hex)
    const token = crypto.randomBytes(32).toString('hex');

    // Sauvegarde le token et sa date d'expiration (1 heure) dans la base de données
    user.resetToken = token;
    user.resetTokenExpiration = Date.now() + 3600000; // 1h en millisecondes
    await user.save();

    // Lien que l'utilisateur va recevoir dans l'email
    const resetLink = `${process.env.FRONTEND_URL}/Pages/reset-password.html?token=${token}`;

    // Contenu HTML de l'email
    const html = `
      <h2>Réinitialisation de mot de passe - Scola</h2>
      <p>Bonjour ${user.name},</p>
      <p>Clique sur le bouton ci-dessous pour réinitialiser ton mot de passe :</p>
      <a href="${resetLink}" style="
        display: inline-block;
        padding: 12px 24px;
        background-color: #4f46e5;
        color: white;
        text-decoration: none;
        border-radius: 6px;
        font-weight: bold;
      ">Réinitialiser mon mot de passe</a>
      <p>Ce lien expire dans <strong>1 heure</strong>.</p>
      <p>Si tu n'as pas fait cette demande, ignore cet email.</p>
    `;

    await sendEmail(user.email, user.name, "Réinitialisation de mot de passe", html);

    res.status(200).json({ message: "Si cet email existe, un lien a été envoyé." });

  } catch (err) {
    console.error("Erreur forgot-password :", err);
    res.status(500).json({ message: "Erreur serveur." });
  }
});

// ─────────────────────────────────────────────
// POST /api/auth/reset-password
// L'utilisateur envoie le token + nouveau mot de passe → on met à jour
// ─────────────────────────────────────────────
router.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;

  try {
    // Cherche un utilisateur avec ce token qui n'a pas encore expiré
    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiration: { $gt: Date.now() } // $gt = "greater than" = supérieur à maintenant
    });

    if (!user) {
      return res.status(400).json({ message: "Token invalide ou expiré." });
    }

    // Hache le nouveau mot de passe avant de le sauvegarder
    const hashed = await bcrypt.hash(password, 10);
    user.password = hashed;

    // Supprime le token — il ne peut être utilisé qu'une seule fois
    user.resetToken = null;
    user.resetTokenExpiration = null;

    await user.save();

    res.status(200).json({ message: "Mot de passe réinitialisé avec succès." });

  } catch (err) {
    console.error("Erreur reset-password :", err);
    res.status(500).json({ message: "Erreur serveur." });
  }
});

module.exports = router;