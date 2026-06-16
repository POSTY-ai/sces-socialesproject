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
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const User = require("./models/user");
const cron = require("node-cron");


const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS
    }
});

// ================================
// MIDDLEWARES
// ================================

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, "../ALLPAGES")));

// ================================
// PAGE D'ACCUEIL
// ================================

app.get("/", (req, res) => {
  res.sendFile(
    path.join(__dirname, "../ALLPAGES/index.html")
);
});

// ================================
// INSCRIPTION
// ================================

app.post("/inscription", async (req, res) => {

    try {

        const { name, email, password } = req.body;

           //valider nom

        // Minimum 2 caractères, lettres et espaces seulement, pas de chiffres
const nomRegex = /^[a-zA-ZÀ-ÿ\s]{2,50}$/;
if (!nomRegex.test(name)) {
    return res.status(400).json({
        message: "Le nom doit contenir entre 2 et 50 lettres, sans chiffres ni caractères spéciaux."
    });
}

        //valider email
        // Format standard : quelquechose@domaine.extension
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
if (!emailRegex.test(email)) {
    return res.status(400).json({
        message: "Adresse email invalide."
    });
}

        // Validation du mot de passe : min 8 chars, 1 majuscule, 1 minuscule, 1 chiffre
        const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
        if (!passwordRegex.test(password)) {
            return res.status(400).json({
                message: "Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule et un chiffre."
            });
        }

        // Vérifie si l'email existe déjà dans MongoDB
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: "Email déjà utilisé" });
        }

        // Hachage du mot de passe — 10 = niveau de sécurité (salt rounds)
        const hashedPassword = await bcrypt.hash(password, 10);

        const newUser = new User({ name, email, password: hashedPassword });
        await newUser.save();

        const token = jwt.sign(
    { email: newUser.email },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
);

        console.log("✅ Nouvel utilisateur :", email);
        res.status(200).json({
    message: "Inscription réussie",
    token
});

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

        // bcrypt.compare = compare le mot de passe entré avec le hash stocké
        const match = await bcrypt.compare(password, user.password);
        if (!match) {
            return res.status(401).json({ message: "Mot de passe incorrect" });
        }

        // jwt.sign = crée un token avec les infos de l'utilisateur
        // Ce token sera envoyé à chaque requête pour prouver l'identité
        const token = jwt.sign(
            { email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "7d" } // expire dans 7 jours
        );

        res.status(200).json({ message: "Connexion réussie", token });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// MIDDLEWARE AUTH
// Vérifie le token JWT avant d'accéder aux routes protégées
// S'utilise comme : app.get("/route", auth, handler)
// ================================

function auth(req, res, next) {

    const authHeader = req.headers.authorization;
    if (!authHeader) {
        return res.status(401).json({ message: "Accès refusé — token manquant" });
    }

    // Le header ressemble à "Bearer eyJhbGci..." — on prend la partie après "Bearer "
    const token = authHeader.replace("Bearer ", "");

    try {
        // jwt.verify = décode et vérifie le token. Lance une erreur si invalide ou expiré
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded; // on attache les infos décodées à la requête
        next(); // tout est ok, on passe à la route
    } catch (err) {
        return res.status(401).json({ message: "Token invalide ou expiré" });
    }

}

// ================================
// DASHBOARD
// ================================

app.get("/dashboard", auth, (req, res) => {
    res.sendFile(path.join(__dirname, "../ALLPAGES/Pages/dashboard.html"));
});

// ================================
// PROFIL UTILISATEUR
// Retourne toutes les données du profil pour la page profile.html
// Route protégée — nécessite d'être connecté
// ================================

app.get("/api/profile", auth, async (req, res) => {

    try {

        // Chercher l'utilisateur dans MongoDB par son email (décodé du token)
        const user = await User.findOne({ email: req.user.email });

        if (!user) {
            return res.status(404).json({ message: "Utilisateur introuvable" });
        }

        // Calculer le classement de cet utilisateur
        // On trie tous les users par XP décroissant et on trouve sa position
        const classement = await User.find().sort({ "weeklyLeague.xp": -1 });
        const rank = classement.findIndex(u => u.email === user.email) + 1;
        // findIndex retourne -1 si pas trouvé, +1 pour avoir un rang qui commence à 1

        // Compter les badges débloqués
        // On renvoie les stats brutes — le frontend calcule les badges lui-même
        res.json({

            // Infos personnelles
            name: user.name,
            email: user.email,
            createdAt: user.createdAt,

            // Stats de la ligue
            xp: user.weeklyLeague.xp,
            xpToday: user.weeklyLeague.xpToday,
            streak: user.weeklyLeague.streak,
            league: user.weeklyLeague.league,
            lastActivity: user.weeklyLeague.lastActivity,

            // Classement
            rank,
            totalPlayers: classement.length

        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// MODIFIER LE PROFIL
// Permet de changer le nom de l'utilisateur
// Route protégée
// ================================

app.put("/api/profile", auth, async (req, res) => {

    try {

        const { name } = req.body;


        if (!name || name.trim() === "") {
            return res.status(400).json({ message: "Le nom ne peut pas être vide" });
        }

        // findOneAndUpdate = trouve ET modifie en une seule opération
        // { new: true } = retourne le document APRÈS modification
        const user = await User.findOneAndUpdate(
            { email: req.user.email },
            { $set: { name: name.trim() } },
            { new: true }
        );

        res.json({ message: "Profil mis à jour", name: user.name });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// AJOUTER XP
// Appelé depuis jouer.html à la fin de chaque session
// ================================

app.post("/api/ajouter-xp", auth, async (req, res) => {

    try {

        const points = Number(req.body.pointsGagnes);
        console.log("Points reçus =", points);

        const user = await User.findOne({ email: req.user.email });
        console.log("XP avant =", user.weeklyLeague.xp);

        // Ajouter les points
        user.weeklyLeague.xp = Number(user.weeklyLeague.xp) + points;
        user.weeklyLeague.xpToday = Number(user.weeklyLeague.xpToday) + points;

        console.log("XP après =", user.weeklyLeague.xp);

        // Mise à jour automatique de la ligue selon les seuils XP
        if (user.weeklyLeague.xp >= 500)  user.weeklyLeague.league = "Argent";
        if (user.weeklyLeague.xp >= 1000) user.weeklyLeague.league = "Or";
        if (user.weeklyLeague.xp >= 2000) user.weeklyLeague.league = "Platine";
        if (user.weeklyLeague.xp >= 5000) user.weeklyLeague.league = "Diamant";

        // XP de la semaine
user.weeklyLeague.xp += points;
user.weeklyLeague.xpToday += points;

// ← AJOUTE CETTE LIGNE — XP total à vie
user.xpTotal = (user.xpTotal || 0) + points;

        // Calcul du streak (jours consécutifs)
        const today = new Date();
        if (!user.weeklyLeague.lastActivity) {
            user.weeklyLeague.streak = 1;
        } else {
            const lastDate = new Date(user.weeklyLeague.lastActivity);
            const diffDays = Math.floor((today - lastDate) / (1000 * 60 * 60 * 24));
            // diffDays = nombre de jours entre la dernière activité et aujourd'hui
            if (diffDays === 1) user.weeklyLeague.streak += 1;   // jour suivant = continue le streak
            else if (diffDays > 1) user.weeklyLeague.streak = 1; // saut = repart à 1
        }

        user.weeklyLeague.lastActivity = today;
        user.dailyQuiz.lastPlayed = new Date();

        await user.save();

        res.json({
            message: "XP ajoutés avec succès",
            xp: user.weeklyLeague.xp,
            league: user.weeklyLeague.league,
            streak: user.weeklyLeague.streak
        });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// PROFIL LIGUE DU JOUEUR (liguebac.html)
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
// TOP 3 DE LA LIGUE
// ================================

app.get("/api/league/top", async (req, res) => {

    try {
        // .limit(3) = retourne seulement les 3 premiers
        const top = await User.find().sort({ "weeklyLeague.xp": -1 }).limit(3);
        res.json(top);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// CLASSEMENT COMPLET
// ================================

app.get("/api/league/leaderboard", async (req, res) => {

    try {
        // .limit(30) = max 30 joueurs dans un groupe de ligue
        const users = await User.find().sort({ "weeklyLeague.xp": -1 }).limit(30);
        res.json(users);
    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});

// ================================
// VÉRIFICATION QUIZ JOURNALIER
// Vérifie si l'élève peut encore jouer aujourd'hui
// ================================

app.get("/api/quiz/check", auth, async (req, res) => {

    try {

        const user = await User.findOne({ email: req.user.email });

        const today = new Date();
        today.setHours(0, 0, 0, 0); // début de la journée à minuit

        if (user.dailyQuiz.lastPlayed) {
            const lastPlayed = new Date(user.dailyQuiz.lastPlayed);
            lastPlayed.setHours(0, 0, 0, 0);
            // .getTime() = convertit la date en millisecondes pour comparer
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
// RESET LIGUE (à appeler manuellement ou via cron)
// ================================

app.get("/reset-league", async (req, res) => {

    await User.updateMany({}, {
        $set: {
            "weeklyLeague.xp": 0,
            "weeklyLeague.xpToday": 0
        }
    });

    res.send("✅ Ligue réinitialisée");

});

// ================================
// RÉCOMPENSE TOP 3
// ================================

app.get("/recompense-top3", async (req, res) => {

    const top = await User.find().sort({ "weeklyLeague.xp": -1 }).limit(3);

    if (top[0]) top[0].weeklyLeague.xp += 300;
    if (top[1]) top[1].weeklyLeague.xp += 200;
    if (top[2]) top[2].weeklyLeague.xp += 100;

    for (const joueur of top) {
        await joueur.save();
    }

    res.send("✅ Récompenses distribuées");

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
                    league: "Bronze", lastActivity: null
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

        // Toujours répondre pareil pour la sécurité
        if (!user) {
            return res.json({
                message: "Si un compte existe, un email a été envoyé."
            });
        }

        // Générer un token unique
        const token = crypto.randomBytes(32).toString("hex");

        // Expire dans 1 heure
        user.resetToken = token;
        user.resetTokenExpiration = Date.now() + 3600000;

        await user.save();

        const resetLink =
            `https://scola.onrender.com/new-password.html?token=${token}`;

        await transporter.sendMail({

            from: process.env.EMAIL_USER,
            to: user.email,

            subject: "Réinitialisation du mot de passe Scola",

            html: `
                <h2>Réinitialisation du mot de passe</h2>

                <p>Bonjour ${user.name},</p>

                <p>
                    Tu as demandé une réinitialisation de ton mot de passe.
                </p>

                <p>
                    Clique sur le bouton ci-dessous :
                </p>

                <a href="${resetLink}"
                   style="
                   display:inline-block;
                   padding:12px 20px;
                   background:#2563eb;
                   color:white;
                   text-decoration:none;
                   border-radius:6px;">
                   Réinitialiser mon mot de passe
                </a>

                <p>
                    Ce lien expire dans 1 heure.
                </p>
            `
        });

        res.json({
            message: "Si un compte existe, un email a été envoyé."
        });

    } catch (err) {

        console.error("ERREUR RESET PASSWORD :");
        console.error(err);

        res.status(500).json({
            error: err.message
        });

    }

});

// ================================
// CONNEXION MONGODB
// ================================

mongoose.connect(process.env.MONGO_URI)
    .then(() => console.log("✅ MongoDB connecté"))
    .catch((err) => console.log("❌ Erreur MongoDB :", err));


cron.schedule("59 23 * * 5", async () => {
    await User.updateMany({}, {
        $set: {
            "weeklyLeague.xp": 0,
            "weeklyLeague.xpToday": 0
        }
    });
    console.log("✅ Ligue réinitialisée automatiquement !");
});
// ================================
// DÉMARRAGE SERVEUR
// ================================
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
    console.log(`🚀 Serveur démarré sur le port ${PORT}`);
});

// ================================
// MODIFIER EMAIL + NOM
// PUT /api/profile
// ================================

app.put("/api/profile", auth, async (req, res) => {

    try {

        const { name, email } = req.body;
           //valider nom

        // Minimum 2 caractères, lettres et espaces seulement, pas de chiffres
const nomRegex = /^[a-zA-ZÀ-ÿ\s]{2,50}$/;
if (!nomRegex.test(name)) {
    return res.status(400).json({
        message: "Le nom doit contenir entre 2 et 50 lettres, sans chiffres ni caractères spéciaux."
    });
}

        //valider email
        // Format standard : quelquechose@domaine.extension
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
if (!emailRegex.test(email)) {
    return res.status(400).json({
        message: "Adresse email invalide."
    });
}

        if (!name || !email) {
            return res.status(400).json({ message: "Nom et email obligatoires" });
        }

        // Vérifier si le nouvel email est déjà utilisé par quelqu'un d'autre
        const emailExistant = await User.findOne({
            email,
            _id: { $ne: req.user._id }
            // $ne = "not equal" — exclut l'utilisateur actuel de la recherche
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
// CHANGER MOT DE PASSE
// PUT /api/profile/password
// ================================

app.put("/api/profile/password", auth, async (req, res) => {

    try {

        const { ancienMotDePasse, nouveauMotDePasse } = req.body;

        const user = await User.findOne({ email: req.user.email });
        if (!user) return res.status(404).json({ message: "Utilisateur introuvable" });

        // Vérifier que l'ancien mot de passe est correct
        const match = await bcrypt.compare(ancienMotDePasse, user.password);
        if (!match) {
            return res.status(401).json({ message: "Mot de passe actuel incorrect" });
        }

     

        // Valider le nouveau mot de passe
        const mdpRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$/;
        if (!mdpRegex.test(nouveauMotDePasse)) {
            return res.status(400).json({
                message: "Le mot de passe doit contenir au moins 8 caractères, une majuscule, une minuscule et un chiffre."
            });
        }

        // Hacher le nouveau mot de passe avant de sauvegarder
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
// SUPPRIMER LE COMPTE
// DELETE /api/profile
// ================================

app.delete("/api/profile", auth, async (req, res) => {

    try {

        // deleteOne = supprime le document correspondant dans MongoDB
        await User.deleteOne({ email: req.user.email });

        console.log("🗑️ Compte supprimé :", req.user.email);
        res.json({ message: "Compte supprimé avec succès" });

    } catch (err) {
        console.log(err);
        res.status(500).json({ message: "Erreur serveur" });
    }

});