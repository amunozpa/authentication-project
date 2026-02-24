/**
 * Servicio de Email — Fase 3
 * Dev: log por consola (tokens visibles para testing).
 * Prod (Fase 5.7+): envío real con Nodemailer + Gmail SMTP.
 *
 * Nota: las credenciales Gmail se piden al usuario en Fase 5.7.
 */
import { logger } from '../logger';
import { config } from '../config/env';

// ── Plantillas ────────────────────────────────────────────────────────────────

function verificationTemplate(email: string, url: string): string {
  return `
    Para verificar tu cuenta (${email}), haz clic en el siguiente enlace:
    ${url}

    Este enlace expira en 24 horas.
    Si no creaste esta cuenta, ignora este mensaje.
  `.trim();
}

function passwordResetTemplate(email: string, url: string): string {
  return `
    Recibiste este mensaje porque solicitaste restablecer tu contraseña (${email}).

    Haz clic aquí para elegir una nueva contraseña:
    ${url}

    Este enlace expira en 1 hora.
    Si no solicitaste esto, ignora este mensaje — tu cuenta está segura.
  `.trim();
}

function magicLinkTemplate(email: string, url: string): string {
  return `
    Tu enlace de acceso sin contraseña para (${email}):
    ${url}

    Este enlace expira en 10 minutos y solo funciona una vez.
    Si no solicitaste esto, ignora este mensaje.
  `.trim();
}

// ── Inicializar Nodemailer (solo cuando las credenciales estén disponibles) ───

async function getMailer() {
  if (!config.GMAIL_USER || !config.GMAIL_APP_PASSWORD) return null;

  const nodemailer = await import('nodemailer');
  return nodemailer.default.createTransport({
    service: 'gmail',
    auth: {
      user: config.GMAIL_USER,
      pass: config.GMAIL_APP_PASSWORD,
    },
  });
}

// ── Función de envío unificada ────────────────────────────────────────────────

async function sendEmail(params: {
  to: string;
  subject: string;
  text: string;
  logLabel: string;
  logUrl: string;
}): Promise<void> {
  const mailer = await getMailer();

  if (mailer) {
    // Producción / Fase 5.7+: envío real
    await mailer.sendMail({
      from: `"Auth Lab" <${config.GMAIL_USER}>`,
      to: params.to,
      subject: params.subject,
      text: params.text,
    });
    logger.info({ to: params.to, subject: params.subject }, `Email enviado: ${params.logLabel}`);
  } else {
    // Desarrollo: log por consola — el token es visible para facilitar testing
    logger.info(
      { to: params.to },
      `[${params.logLabel}] ${params.logUrl}`,
    );
  }
}

// ── API pública ───────────────────────────────────────────────────────────────

export async function sendVerificationEmail(email: string, token: string): Promise<void> {
  const url = `${config.FRONTEND_URL}/api/v1/auth/verify-email?token=${token}`;
  await sendEmail({
    to: email,
    subject: 'Verifica tu cuenta — Auth Lab',
    text: verificationTemplate(email, url),
    logLabel: 'VERIFICACION_EMAIL',
    logUrl: url,
  });
}

export async function sendPasswordResetEmail(email: string, token: string): Promise<void> {
  const url = `${config.FRONTEND_URL}/reset-password?token=${token}`;
  await sendEmail({
    to: email,
    subject: 'Restablece tu contraseña — Auth Lab',
    text: passwordResetTemplate(email, url),
    logLabel: 'RESET_PASSWORD',
    logUrl: url,
  });
}

export async function sendMagicLinkEmail(email: string, token: string): Promise<void> {
  const url = `${config.FRONTEND_URL}/api/v1/magic/verify?token=${token}`;
  await sendEmail({
    to: email,
    subject: 'Tu enlace de acceso — Auth Lab',
    text: magicLinkTemplate(email, url),
    logLabel: 'MAGIC_LINK',
    logUrl: url,
  });
}
