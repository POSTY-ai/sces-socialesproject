const SibApiV3Sdk = require('@getbrevo/brevo');

// Configuration de l'API Brevo avec la clé dans .env
const apiInstance = new SibApiV3Sdk.TransactionalEmailsApi();
apiInstance.authentications['apiKey'].apiKey = process.env.BREVO_API_KEY;

/**
 * Envoie un email transactionnel via Brevo (API HTTP, pas SMTP)
 * @param {string} toEmail - Email du destinataire
 * @param {string} toName - Nom du destinataire
 * @param {string} subject - Sujet de l'email
 * @param {string} htmlContent - Corps de l'email en HTML
 */
async function sendEmail(toEmail, toName, subject, htmlContent) {
  const email = new SibApiV3Sdk.SendSmtpEmail();

  email.sender = {
    name: "Scola",
    email: "noreply@scola.ht" // Change si tu as un email vérifié dans Brevo
  };

  email.to = [{ email: toEmail, name: toName }];
  email.subject = subject;
  email.htmlContent = htmlContent;

  const result = await apiInstance.sendTransacEmail(email);
  return result;
}

module.exports = sendEmail;