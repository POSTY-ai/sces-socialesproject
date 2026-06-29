const mongoose = require("mongoose");

const userSchema = new mongoose.Schema({

    name: {
        type: String,
        required: true
    },

    email: {
        type: String,
        required: true,
        unique: true
    },

    password: {
        type: String,
        required: true
    },

    // ================================
    // SYSTÈME PREMIUM
    // role = "gratuit" | "pro" | "ia"
    // premiumExpiry = date d'expiration de l'abonnement
    // ================================
    role: {
        type: String,
        enum: ["gratuit", "pro", "ia"],
        default: "gratuit"
    },

    premiumExpiry: {
        type: Date,
        default: null
    },

    weeklyLeague: {

        xp: {
            type: Number,
            default: 0
        },

        xpToday: {
            type: Number,
            default: 0
        },

        streak: {
            type: Number,
            default: 0
        },

        league: {
            type: String,
            default: "Bronze"
        },

        lastActivity: {
            type: Date,
            default: null
        },
    weekStartDate: { type: Date, default: null }

    },

    dailyQuiz: {

        lastPlayed: {
            type: Date,
            default: null
        },

        // Nombre de quiz joués aujourd'hui (pour limiter les gratuits)
        countToday: {
            type: Number,
            default: 0
        },

        lastCountReset: {
            type: Date,
            default: null
        }

    },

    // XP total à vie
    xpTotal: {
        type: Number,
        default: 0
    },

    resetToken: {
        type: String,
        default: null
    },

    resetTokenExpiration: {
        type: Date,
        default: null
    }

}, { timestamps: true });

module.exports = mongoose.model("User", userSchema);