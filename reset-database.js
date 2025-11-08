// Reset complet de la base de données
const Database = require('better-sqlite3');

const db = new Database('data/alerts.db');

console.log('💥 Complete database reset...');

try {
  // Supprimer toutes les données
  console.log('Deleting all data...');
  
  const deleteAlerts = db.prepare('DELETE FROM alerts');
  const alertsResult = deleteAlerts.run();
  console.log('Deleted alerts:', alertsResult.changes);
  
  const deleteRules = db.prepare('DELETE FROM rules');
  const rulesResult = deleteRules.run();
  console.log('Deleted rules:', rulesResult.changes);
  
  const deleteWebhooks = db.prepare('DELETE FROM user_webhooks');
  const webhooksResult = deleteWebhooks.run();
  console.log('Deleted webhooks:', webhooksResult.changes);
  
  const deleteUsers = db.prepare('DELETE FROM users');
  const usersResult = deleteUsers.run();
  console.log('Deleted users:', usersResult.changes);
  
  // Reset les auto-increment
  console.log('\\nResetting auto-increment counters...');
  
  db.prepare('DELETE FROM sqlite_sequence WHERE name = "alerts"').run();
  db.prepare('DELETE FROM sqlite_sequence WHERE name = "rules"').run();
  db.prepare('DELETE FROM sqlite_sequence WHERE name = "user_webhooks"').run();
  db.prepare('DELETE FROM sqlite_sequence WHERE name = "users"').run();
  
  // Vérification
  console.log('\\nVerifying database is empty...');
  
  const countUsers = db.prepare('SELECT COUNT(*) as count FROM users').get();
  const countWebhooks = db.prepare('SELECT COUNT(*) as count FROM user_webhooks').get();
  const countRules = db.prepare('SELECT COUNT(*) as count FROM rules').get();
  const countAlerts = db.prepare('SELECT COUNT(*) as count FROM alerts').get();
  
  console.log('Users remaining:', countUsers.count);
  console.log('Webhooks remaining:', countWebhooks.count);
  console.log('Rules remaining:', countRules.count);
  console.log('Alerts remaining:', countAlerts.count);
  
  const totalRecords = countUsers.count + countWebhooks.count + countRules.count + countAlerts.count;
  
  if (totalRecords === 0) {
    console.log('\\n✅ Database completely reset - all tables are empty!');
    console.log('🎯 Ready for fresh start with clean IDs starting from 1');
  } else {
    console.log('\\n⚠️  Some records may still exist');
  }
  
} catch (error) {
  console.error('Reset failed:', error.message);
} finally {
  db.close();
}