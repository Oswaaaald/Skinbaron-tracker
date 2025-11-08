// Nettoyer la base pour repartir proprement
const Database = require('better-sqlite3');

const db = new Database('data/alerts.db');

console.log('🧹 Cleaning database for fresh test...');

// Supprimer tous les webhooks
const deleteWebhooks = db.prepare('DELETE FROM user_webhooks');
const webhooksResult = deleteWebhooks.run();
console.log('Deleted webhooks:', webhooksResult.changes);

// Supprimer toutes les rules
const deleteRules = db.prepare('DELETE FROM rules');
const rulesResult = deleteRules.run();
console.log('Deleted rules:', rulesResult.changes);

// Garder seulement l'utilisateur testnew (id=5) et supprimer les autres
const deleteOtherUsers = db.prepare('DELETE FROM users WHERE id != 5');
const usersResult = deleteOtherUsers.run();
console.log('Deleted other users:', usersResult.changes);

// Vérifier ce qui reste
const remainingUsers = db.prepare('SELECT id, username, email FROM users').all();
console.log('Remaining users:', remainingUsers);

const remainingWebhooks = db.prepare('SELECT COUNT(*) as count FROM user_webhooks').get();
console.log('Remaining webhooks:', remainingWebhooks.count);

const remainingRules = db.prepare('SELECT COUNT(*) as count FROM rules').get();
console.log('Remaining rules:', remainingRules.count);

db.close();
console.log('✅ Database cleaned for fresh test');