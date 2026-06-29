// ================================
// IMPORTATIONS
// ================================

const express = require("express");
const app = express();
const mongoose = require("mongoose");
require("dotenv").config();
const path = require("path");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require('cors');
const crypto = require("crypto");
const User = require("./models/user");
const cron = require("node-cron");

// Envoi email via API HTTP Brevo (fetch natif, pas de SDK)
async function sendEmail(toEmail, toName, subject, htmlContent) {
    const response = await fetch("https://api.brevo.com/v3/smtp/email", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "api-key": process.env.BREVO_API_KEY
        },
        body: JSON.stringify({
            sender: { name: "Scola", email: "noreply@scola.ht" },
            to: [{ email: toEmail, name: toName }],
            subject: subject,
            htmlContent: htmlContent
        })
    });

    if (!response.ok) {
        const err = await response.json();
        throw new Error(JSON.stringify(err));
    }

    return await response.json();
}

// ================================
// MIDDLEWARES
// ================================
app.use(cors({ origin: 'https://scola.onrender.com' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "../ALLPAGES")));

// ================================
// PAGE D'ACCUEIL
// ================================

app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "../ALLPAGES/index.html"));
});

// ================================
// INSCRIPTION
// ================================

app.post("/inscription", async (req, res) => {

    try {

        const { name, email, password } = req.body;

        // Minimum 2 caractères, lettres et espaces seulement, pas de chiffres
        const nomRegex = /^[a-zA-ZÀ-ÿ\s]{2,50}$/;
        if (!nomRegex.test(name)) {
            return res.status(400).json({
                message: "Le nom doit contenir entre 2 et 50 lettres, sans chiffres ni caractères spéciaux."
            });
        }

        // Format standard : quelquechose@domaine.extension
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: "Adresse email invalide." });
        }

        // Validation du mot de passe : min 8 chars, 1 majuscule, 1 minuscule, 1 chiffre
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                message: "Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule et un chiffre."
            });
        }

        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "Email déjà utilisé" });
        }

        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();

        const token = jwt.sign(
            { email: newUser.email },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        console.log("✅ Nouvel utilisateur :", email);
        res.status(200).json({ message: "Inscription réussie", token });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// CONNEXION
// ================================

app.post("/register", async (req, res) => {

    try {

        const { email, password } = req.body;

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: "Utilisateur introuvable" });
        }

        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ message: "Mot de passe incorrect" });
        }

        const token = jwt.sign(
            { email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "7d" }
        );

        res.status(200).json({ message: "Connexion réussie", token });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// MIDDLEWARE AUTH
// ================================

function auth(req, res, next) {

    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: "Accès refusé — token manquant" });
    }

    const token = authHeader.replace("Bearer ", "");

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (err) {
        return res.status(401).json({ message: "Token invalide ou expiré" });
    }

}

// ================================
// MIDDLEWARE PREMIUM
// ================================

function checkPremium(rolesAutorises) {
    return async (req, res, next) => {

        try {
            const user = await User.findOne({ email: req.user.email });

            if (!user) {
                return res.status(404).json({ message: "Utilisateur introuvable" });
            }

            if (user.premiumExpiry && new Date() > new Date(user.premiumExpiry)) {
                user.role = "gratuit";
                user.premiumExpiry = null;
                await user.save();
                return res.status(403).json({
                    locked: true,
                    message: "Ton abonnement a expiré. Renouvelle pour continuer."
                });
            }

            if (!rolesAutorises.includes(user.role)) {
                return res.status(403).json({
                    locked: true,
                    role: user.role,
                    message: "Cette fonctionnalité est réservée aux membres premium."
                });
            }

            req.userDoc = user;
            next();

        } catch (err) {
            console.log(err);
            res.status(500).json({ message: "Erreur serveur" });
        }
    };
}

// ================================
// GET /api/me
// ================================

app.get("/api/me", auth, async (req, res) => {

    try {

        const user = await User.findOne({ email: req.user.email });
        if (!user) return res.status(404).json({ message: "Utilisateur introuvable" });

        let role = user.role;
        let premiumExpiry = user.premiumExpiry;

        if (premiumExpiry && new Date() > new Date(premiumExpiry)) {
            role = "gratuit";
            premiumExpiry = null;
            user.role = "gratuit";
            user.premiumExpiry = null;
            await user.save();
        }

        res.json({
            name: user.name,
            email: user.email,
            role,
            premiumExpiry,
            isPro: ["pro", "ia"].includes(role),
            isIA: role === "ia"
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// POST /api/premium/activer (admin)
// ================================

app.post("/api/premium/activer", auth, async (req, res) => {

    try {

        const { email, tier, dureeJours } = req.body;

        const ADMIN_EMAILS = ["jonathanfortune07@gmail.com"];
        if (!ADMIN_EMAILS.includes(req.user.email)) {
            return res.status(403).json({ message: "Accès refusé" });
        }

        const cible = await User.findOne({ email });
        if (!cible) return res.status(404).json({ message: "Utilisateur introuvable" });

        const expiry = new Date();
        expiry.setDate(expiry.getDate() + Number(dureeJours));

        cible.role = tier;
        cible.premiumExpiry = expiry;
        await cible.save();

        console.log(`✅ Premium activé pour ${email} — tier: ${tier} — expire: ${expiry}`);
        res.json({ message: `Premium ${tier} activé pour ${email}`, expiry });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// GET /api/examens
// ================================

app.get("/api/examens", auth, async (req, res) => {

    try {

        const user = await User.findOne({ email: req.user.email });

        if (user.premiumExpiry && new Date() > new Date(user.premiumExpiry)) {
            user.role = "gratuit";
            user.premiumExpiry = null;
            await user.save();
        }

        const tousLesExamens = [
            { id: 1, titre: "Bac 2024 — Session 1", annee: 2024, driveId: "DRIVE_ID_1", gratuit: true },
            { id: 2, titre: "Bac 2024 — Session 2", annee: 2024, driveId: "DRIVE_ID_2", gratuit: true },
            { id: 3, titre: "Bac 2023 — Session 1", annee: 2023, driveId: "DRIVE_ID_3", gratuit: true },
            { id: 4, titre: "Bac 2023 — Session 2", annee: 2023, driveId: "DRIVE_ID_4", gratuit: false },
            { id: 5, titre: "Bac 2022 — Session 1", annee: 2022, driveId: "DRIVE_ID_5", gratuit: false },
            { id: 6, titre: "Bac 2022 — Session 2", annee: 2022, driveId: "DRIVE_ID_6", gratuit: false },
            { id: 7, titre: "Bac 2021 — Session 1", annee: 2021, driveId: "DRIVE_ID_7", gratuit: false },
            { id: 8, titre: "Bac 2021 — Session 2", annee: 2021, driveId: "DRIVE_ID_8", gratuit: false },
            { id: 9, titre: "Bac 2020 — Session 1", annee: 2020, driveId: "DRIVE_ID_9", gratuit: false },
            { id: 10, titre: "Bac 2020 — Session 2", annee: 2020, driveId: "DRIVE_ID_10", gratuit: false },
            { id: 11, titre: "Bac 2019 — Session 1", annee: 2019, driveId: "DRIVE_ID_11", gratuit: false },
            { id: 12, titre: "Bac 2019 — Session 2", annee: 2019, driveId: "DRIVE_ID_12", gratuit: false },
            { id: 13, titre: "Bac 2018 — Session 1", annee: 2018, driveId: "DRIVE_ID_13", gratuit: false },
            { id: 14, titre: "Bac 2018 — Session 2", annee: 2018, driveId: "DRIVE_ID_14", gratuit: false },
            { id: 15, titre: "Bac 2017 — Session 1", annee: 2017, driveId: "DRIVE_ID_15", gratuit: false },
            { id: 16, titre: "Bac 2017 — Session 2", annee: 2017, driveId: "DRIVE_ID_16", gratuit: false },
            { id: 17, titre: "Bac 2016 — Session 1", annee: 2016, driveId: "DRIVE_ID_17", gratuit: false },
            { id: 18, titre: "Bac 2016 — Session 2", annee: 2016, driveId: "DRIVE_ID_18", gratuit: false },
        ];

        const estPremium = ["pro", "ia"].includes(user.role);

        if (estPremium) {
            return res.json({ role: user.role, examens: tousLesExamens });
        } else {
            const examensGratuits = tousLesExamens.map(e => ({
                ...e,
                driveId: e.gratuit ? e.driveId : null,
                locked: !e.gratuit
            }));
            return res.json({ role: user.role, examens: examensGratuits });
        }

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// GET /api/quiz/check-pro
// ================================

app.get("/api/quiz/check-pro", auth, async (req, res) => {

    try {

        const user = await User.findOne({ email: req.user.email });
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        if (["pro", "ia"].includes(user.role)) {
            return res.json({ canPlay: true, role: user.role, limite: false });
        }

        const LIMITE_GRATUIT = 3;

        if (user.dailyQuiz.lastCountReset) {
            const lastReset = new Date(user.dailyQuiz.lastCountReset);
            lastReset.setHours(0, 0, 0, 0);
            if (lastReset.getTime() !== today.getTime()) {
                user.dailyQuiz.countToday = 0;
                user.dailyQuiz.lastCountReset = today;
                await user.save();
            }
        } else {
            user.dailyQuiz.lastCountReset = today;
            await user.save();
        }

        if (user.dailyQuiz.countToday >= LIMITE_GRATUIT) {
            return res.json({
                canPlay: false,
                role: "gratuit",
                limite: true,
                message: `Tu as atteint ta limite de ${LIMITE_GRATUIT} quiz aujourd'hui. Passe à Pro pour jouer sans limite !`
            });
        }

        res.json({
            canPlay: true,
            role: "gratuit",
            limite: false,
            restants: LIMITE_GRATUIT - user.dailyQuiz.countToday
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// POST /api/quiz/increment
// ================================

app.post("/api/quiz/increment", auth, async (req, res) => {

    try {

        const user = await User.findOne({ email: req.user.email });

        if (["pro", "ia"].includes(user.role)) {
            return res.json({ message: "OK" });
        }

        user.dailyQuiz.countToday = (user.dailyQuiz.countToday || 0) + 1;
        await user.save();

        res.json({ countToday: user.dailyQuiz.countToday });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// GET /api/chapitres/:id
// ================================

app.get("/api/chapitres/:id", auth, async (req, res) => {

    try {

        const user = await User.findOne({ email: req.user.email });
        const estPremium = ["pro", "ia"].includes(user.role);

        const chapitre = {
            id: req.params.id,
            titre: "Chapitre demandé",
            introduction: "Contenu d'introduction disponible pour tous...",
            contenuComplet: estPremium ? "Contenu complet avec exercices, résumés et quiz..." : null,
            locked: !estPremium
        };

        res.json({ role: user.role, chapitre });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// POST /api/premium/desactiver (admin)
// ================================

app.post("/api/premium/desactiver", auth, async (req, res) => {

    try {

        const ADMIN_EMAILS = ["jonathanfortune07@gmail.com"];
        if (!ADMIN_EMAILS.includes(req.user.email)) {
            return res.status(403).json({ message: "Accès refusé" });
        }

        const { email } = req.body;
        const cible = await User.findOne({ email });
        if (!cible) return res.status(404).json({ message: "Utilisateur introuvable" });

        cible.role = "gratuit";
        cible.premiumExpiry = null;
        await cible.save();

        res.json({ message: `Premium désactivé pour ${email}` });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// DASHBOARD
// ================================

app.get("/dashboard", auth, (req, res) => {
    res.sendFile(path.join(__dirname, "../ALLPAGES/Pages/dashboard.html"));
});

// ================================
// GET /api/profile
// ================================

app.get("/api/profile", auth, async (req, res) => {

    try {

        const user = await User.findOne({ email: req.user.email });
        if (!user) return res.status(404).json({ message: "Utilisateur introuvable" });

        const classement = await User.find().sort({ "weeklyLeague.xp": -1 });
        const rank = classement.findIndex(u => u.email === user.email) + 1;

        res.json({
            name: user.name,
            email: user.email,
            createdAt: user.createdAt,
            xp: user.weeklyLeague.xp,
            xpToday: user.weeklyLeague.xpToday,
            streak: user.weeklyLeague.streak,
            league: user.weeklyLeague.league,
            lastActivity: user.weeklyLeague.lastActivity,
            rank,
            totalPlayers: classement.length
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// POST /api/ajouter-xp
// ================================

app.post("/api/ajouter-xp", auth, async (req, res) => {

    try {

        const points = Number(req.body.pointsGagnes);
        console.log("Points reçus =", points);

        const user = await User.findOne({ email: req.user.email });
        if (!user) return res.status(404).json({ message: "Utilisateur introuvable" });

        console.log("XP avant =", user.weeklyLeague.xp);

        // Ajout des XP
        user.weeklyLeague.xp = Number(user.weeklyLeague.xp || 0) + points;
        user.weeklyLeague.xpToday = Number(user.weeklyLeague.xpToday || 0) + points;
        user.xpTotal = Number(user.xpTotal || 0) + points;

        console.log("XP après =", user.weeklyLeague.xp);

        // Mise à jour de la ligue selon XP hebdomadaire
        if (user.weeklyLeague.xp >= 5000) {
            user.weeklyLeague.league = "Diamant";
        } else if (user.weeklyLeague.xp >= 2000) {
            user.weeklyLeague.league = "Platine";
        } else if (user.weeklyLeague.xp >= 1000) {
            user.weeklyLeague.league = "Or";
        } else if (user.weeklyLeague.xp >= 500) {
            user.weeklyLeague.league = "Argent";
        } else {
            user.weeklyLeague.league = "Bronze";
        }

        // Calcul du streak
        const today = new Date();

        if (!user.weeklyLeague.lastActivity) {
            user.weeklyLeague.streak = 1;
        } else {
            const lastDate = new Date(user.weeklyLeague.lastActivity);
            const diffDays = Math.floor((today - lastDate) / (1000 * 60 * 60 * 24));

            if (diffDays === 1) {
                user.weeklyLeague.streak += 1;
            } else if (diffDays > 1) {
                user.weeklyLeague.streak = 1;
            }
        }

        user.weeklyLeague.lastActivity = today;
        user.dailyQuiz.lastPlayed = today;

        await user.save();

        res.json({
            message: "XP ajoutés avec succès",
            xp: user.weeklyLeague.xp,
            xpTotal: user.xpTotal,
            league: user.weeklyLeague.league,
            streak: user.weeklyLeague.streak
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// GET /api/league/me
// ================================

app.get("/api/league/me", auth, async (req, res) => {

    try {

        const user = await User.findOne({ email: req.user.email });
        if (!user) return res.status(404).json({ message: "Utilisateur introuvable" });

        const classement = await User.find().sort({ "weeklyLeague.xp": -1 });
        const rank = classement.findIndex(u => u.email === user.email) + 1;

        res.json({
            name: user.name,
            email: user.email,
            xp: user.weeklyLeague.xp,
            xpToday: user.weeklyLeague.xpToday,
            streak: user.weeklyLeague.streak,
            league: user.weeklyLeague.league,
            rank,
            totalPlayers: classement.length
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// GET /api/league/top
// ================================

app.get("/api/league/top", async (req, res) => {

    try {
        const top = await User.find().sort({ "weeklyLeague.xp": -1 }).limit(3);
        res.json(top);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// GET /api/league/leaderboard
// ================================

app.get("/api/league/leaderboard", async (req, res) => {

    try {
        const users = await User.find().sort({ "weeklyLeague.xp": -1 }).limit(30);
        res.json(users);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// GET /api/quiz/check
// ================================

app.get("/api/quiz/check", auth, async (req, res) => {

    try {

        const user = await User.findOne({ email: req.user.email });
        const today = new Date();
        today.setHours(0, 0, 0, 0);

        if (user.dailyQuiz.lastPlayed) {
            const lastPlayed = new Date(user.dailyQuiz.lastPlayed);
            lastPlayed.setHours(0, 0, 0, 0);
            if (lastPlayed.getTime() === today.getTime()) {
                return res.json({ canPlay: false });
            }
        }

        res.json({ canPlay: true });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// FONCTION RESET LIGUE
// Récompense top 3, remet XP à 0, remet league à Bronze
// ================================

async function resetLigue() {

    // 1. Récompenser le top 3 (XP total à vie, pas le weekly)
    const top = await User.find().sort({ "weeklyLeague.xp": -1 }).limit(3);
    const bonus = [300, 200, 100];

    for (let i = 0; i < top.length; i++) {
        top[i].xpTotal = Number(top[i].xpTotal || 0) + bonus[i];
        await top[i].save();
        console.log(`🏆 ${top[i].name} — +${bonus[i]} XP total (place ${i + 1})`);
    }

    // 2. Reset XP hebdomadaire + league pour tous les joueurs
    await User.updateMany({}, {
        $set: {
            "weeklyLeague.xp": 0,
            "weeklyLeague.xpToday": 0,
            "weeklyLeague.league": "Bronze",
            "weeklyLeague.weekStartDate": new Date()
        }
    });

    console.log("✅ Ligue réinitialisée — tous les joueurs remis en Bronze.");
}

// ================================
// POST /api/admin/reset-league (admin seulement)
// Pour déclencher le reset manuellement
// ================================

app.post("/api/admin/reset-league", auth, async (req, res) => {

    const ADMIN_EMAILS = ["jonathanfortune07@gmail.com"];
    if (!ADMIN_EMAILS.includes(req.user.email)) {
        return res.status(403).json({ message: "Accès refusé" });
    }

    try {
        await resetLigue();
        res.json({ success: true, message: "✅ Ligue réinitialisée manuellement." });
    } catch (err) {
        console.error(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// FIX LIGUE — corrige les anciens utilisateurs sans weeklyLeague
// ================================

app.get("/fix-league", async (req, res) => {

    await User.updateMany(
        { weeklyLeague: { $exists: false } },
        {
            $set: {
                weeklyLeague: {
                    xp: 0, xpToday: 0, streak: 0,
                    league: "Bronze", lastActivity: null,
                    weekStartDate: new Date()
                }
            }
        }
    );

    res.send("✅ League corrigée");

});

// ================================
// MOT DE PASSE OUBLIÉ
// ================================

app.post("/api/reset-password", async (req, res) => {

    try {

        const { email } = req.body;
        const user = await User.findOne({ email });

        if (!user) {
            return res.json({ message: "Si un compte existe, un email a été envoyé." });
        }

        const token = crypto.randomBytes(32).toString("hex");

        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000;
        await user.save();

        const resetLink = `https://scola.onrender.com/Pages/reset-password.html?token=${token}`;

        await sendEmail(
            user.email,
            user.name,
            "Réinitialisation du mot de passe Scola",
            `
            <h2>Réinitialisation du mot de passe</h2>
            <p>Bonjour ${user.name},</p>
            <p>Clique sur le bouton ci-dessous pour réinitialiser ton mot de passe :</p>
            <a href="${resetLink}" style="display:inline-block;padding:12px 20px;background:#2563eb;color:white;text-decoration:none;border-radius:6px;">
                Réinitialiser mon mot de passe
            </a>
            <p>Ce lien expire dans 1 heure.</p>
            `
        );

        res.json({ message: "Si un compte existe, un email a été envoyé." });

    } catch (err) {
        console.error("ERREUR RESET PASSWORD :");
        console.error(err);
        res.status(500).json({ error: err.message });
    }

});

// ================================
// CONNEXION MONGODB
// ================================

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB connecté"))
    .catch((err) => console.log("❌ Erreur MongoDB :", err));

// ================================
// CRON — RESET LIGUE AUTOMATIQUE
// Tous les lundis à 00h00
// ================================

cron.schedule("0 0 * * 1", async () => {
    try {
        console.log("⏰ Déclenchement reset ligue automatique...");
        await resetLigue();
    } catch (err) {
        console.error("❌ Erreur reset ligue automatique :", err);
    }
});

// ================================
// DÉMARRAGE SERVEUR
// ================================

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Serveur démarré sur le port ${PORT}`);
});

// ================================
// PUT /api/profile — MODIFIER EMAIL + NOM
// ================================

app.put("/api/profile", auth, async (req, res) => {

    try {

        const { name, email } = req.body;

        const nomRegex = /^[a-zA-ZÀ-ÿ\s]{2,50}$/;
        if (!nomRegex.test(name)) {
            return res.status(400).json({
                message: "Le nom doit contenir entre 2 et 50 lettres, sans chiffres ni caractères spéciaux."
            });
        }

        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
        if (!emailRegex.test(email)) {
            return res.status(400).json({ message: "Adresse email invalide." });
        }

        if (!name || !email) {
            return res.status(400).json({ message: "Nom et email obligatoires" });
        }

        const emailExistant = await User.findOne({
            email,
            _id: { $ne: req.user._id }
        });

        if (emailExistant) {
            return res.status(400).json({ message: "Cet email est déjà utilisé" });
        }

        await User.findOneAndUpdate(
            { email: req.user.email },
            { $set: { name: name.trim(), email: email.trim() } },
            { new: true }
        );

        res.json({ message: "Profil mis à jour", name, email });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// PUT /api/profile/password — CHANGER MOT DE PASSE
// ================================

app.put("/api/profile/password", auth, async (req, res) => {

    try {

        const { ancienMotDePasse, nouveauMotDePasse } = req.body;

        const user = await User.findOne({ email: req.user.email });
        if (!user) return res.status(404).json({ message: "Utilisateur introuvable" });

        const match = await bcrypt.compare(ancienMotDePasse, user.password);
        if (!match) {
            return res.status(401).json({ message: "Mot de passe actuel incorrect" });
        }

        const mdpRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
        if (!mdpRegex.test(nouveauMotDePasse)) {
            return res.status(400).json({
                message: "Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule et un chiffre."
            });
        }

        const hashedNouveauMdp = await bcrypt.hash(nouveauMotDePasse, 10);

        await User.findOneAndUpdate(
            { email: req.user.email },
            { $set: { password: hashedNouveauMdp } }
        );

        res.json({ message: "Mot de passe changé avec succès" });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// DELETE /api/profile — SUPPRIMER LE COMPTE
// ================================

app.delete("/api/profile", auth, async (req, res) => {

    try {

        await User.deleteOne({ email: req.user.email });
        console.log("🗑️ Compte supprimé :", req.user.email);
        res.json({ message: "Compte supprimé avec succès" });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// POST /api/paiement/simuler
// ================================

app.post("/api/paiement/simuler", auth, async (req, res) => {

    try {

        const { tier, montant } = req.body;

        if (!["pro", "ia"].includes(tier)) {
            return res.status(400).json({ message: "Tier invalide" });
        }

        const prixAttendus = { pro: 500, ia: 800 };
        if (montant !== prixAttendus[tier]) {
            return res.status(400).json({ message: "Montant incorrect" });
        }

        const user = await User.findOne({ email: req.user.email });
        if (!user) return res.status(404).json({ message: "Utilisateur introuvable" });

        const expiry = new Date();
        expiry.setDate(expiry.getDate() + 30);

        user.role = tier;
        user.premiumExpiry = expiry;
        await user.save();

        const fakeTransactionId = "SIM-" + Date.now() + "-" + Math.random().toString(36).slice(2, 8).toUpperCase();

        console.log(`✅ [SIMULATION] Premium ${tier} activé pour ${req.user.email} — expire: ${expiry}`);

        res.json({
            message: "Paiement simulé avec succès",
            transactionId: fakeTransactionId,
            tier,
            expiry,
            role: user.role
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// GET /api/paiement/statut
// ================================

app.get("/api/paiement/statut", auth, async (req, res) => {

    try {

        const user = await User.findOne({ email: req.user.email });
        if (!user) return res.status(404).json({ message: "Utilisateur introuvable" });

        if (user.premiumExpiry && new Date() > new Date(user.premiumExpiry)) {
            user.role = "gratuit";
            user.premiumExpiry = null;
            await user.save();
        }

        res.json({
            role: user.role,
            premiumExpiry: user.premiumExpiry,
            isPro: ["pro", "ia"].includes(user.role),
            isIA: user.role === "ia"
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});