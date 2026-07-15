import nodemailer from "nodemailer";
import { config } from "../config.js";

let transporter = null;

export function smtpConfigured() {
  return !!(config.smtp?.host && config.smtp?.user && config.smtp?.pass);
}

function getTransporter() {
  if (!smtpConfigured()) return null;
  if (!transporter) {
    transporter = nodemailer.createTransport({
      host: config.smtp.host,
      port: config.smtp.port,
      secure: config.smtp.secure,
      auth: {
        user: config.smtp.user,
        pass: config.smtp.pass,
      },
    });
  }
  return transporter;
}

/**
 * Send email via SMTP. In non-prod without SMTP, logs to console (dev).
 * In production without SMTP, throws.
 */
export async function sendMail({ to, subject, text, html }) {
  const from = config.smtp.from || config.smtp.user || "Vaultline <noreply@localhost>";
  if (!smtpConfigured()) {
    if (config.isProd) {
      throw new Error("Email is not configured (set SMTP_HOST, SMTP_USER, SMTP_PASS on Render)");
    }
    console.warn("[mail:dev] SMTP not configured — message logged only");
    console.warn(`To: ${to}\nSubject: ${subject}\n${text}`);
    return { queued: false, logged: true };
  }
  const tx = getTransporter();
  await tx.sendMail({ from, to, subject, text, html: html || undefined });
  return { queued: true };
}

export async function sendActivationEmail({ to, name, code, link }) {
  const subject = "Activate your Vaultline account";
  const text = `Hi ${name || ""},

Your Vaultline activation code is: ${code}

Or open this link (expires in 30 minutes):
${link}

If you did not register, ignore this email.`;
  const html = `<p>Hi ${escapeHtml(name || "")},</p>
<p>Your Vaultline activation code is: <strong style="font-size:1.25em;letter-spacing:0.12em">${escapeHtml(code)}</strong></p>
<p><a href="${escapeHtml(link)}">Activate account</a> (expires in 30 minutes)</p>
<p>If you did not register, ignore this email.</p>`;
  return sendMail({ to, subject, text, html });
}

export async function sendPasswordResetEmail({ to, name, code, link }) {
  const subject = "Reset your Vaultline password";
  const text = `Hi ${name || ""},

Your Vaultline password reset code is: ${code}

Or open this link (expires in 30 minutes):
${link}

If you did not request this, ignore this email.`;
  const html = `<p>Hi ${escapeHtml(name || "")},</p>
<p>Your password reset code is: <strong style="font-size:1.25em;letter-spacing:0.12em">${escapeHtml(code)}</strong></p>
<p><a href="${escapeHtml(link)}">Reset password</a> (expires in 30 minutes)</p>
<p>If you did not request this, ignore this email.</p>`;
  return sendMail({ to, subject, text, html });
}

function escapeHtml(s) {
  return String(s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
