# 🧪 Guide de Test SkinBaron API

Ce guide vous aidera à valider que votre clé API SkinBaron fonctionne parfaitement avec l'application.

## 📋 **Méthodes de Test Disponibles**

### 🚀 **1. Test Rapide via Script Node.js**

```bash
# Dans le dossier backend
cd /home/oswaaaald/skinbaron-alerts-sbapi/backend

# Test avec votre clé API
node test-skinbaron-api.js VOTRE_CLE_API

# Ou avec variable d'environnement
SB_API_KEY=VOTRE_CLE_API node test-skinbaron-api.js
```

**Ce que le script teste :**
- ✅ Connexion basique à l'API
- ✅ Recherche d'items (AK-47, AWP Asiimov, Knives)  
- ✅ Endpoint "Best Deals"
- ✅ Endpoint "Newest Items"
- ✅ Temps de réponse
- ✅ Format des données retournées

**Résultats attendus :**
```
🎉 ALL TESTS PASSED! Your API key works perfectly!
🚀 You can now enable SkinBaron monitoring in your app.
```

---

### 🌐 **2. Test via API REST (Application Déployée)**

#### **Test SkinBaron API uniquement :**
```bash
curl -X POST "https://api.skinbaron-tracker.oswaaaald.be/api/test/skinbaron" \
  -H "Content-Type: application/json" \
  -d '{
    "apiKey": "VOTRE_CLE_API",
    "testSearch": "AK-47"
  }'
```

#### **Test Webhook Discord :**
```bash
curl -X POST "https://api.skinbaron-tracker.oswaaaald.be/api/test/webhook" \
  -H "Content-Type: application/json" \
  -d '{
    "webhookUrl": "https://discord.com/api/webhooks/VOTRE_WEBHOOK"
  }'
```

#### **Test Workflow Complet (API + Webhook) :**
```bash
curl -X POST "https://api.skinbaron-tracker.oswaaaald.be/api/test/workflow" \
  -H "Content-Type: application/json" \
  -d '{
    "apiKey": "VOTRE_CLE_API",
    "webhookUrl": "https://discord.com/api/webhooks/VOTRE_WEBHOOK",
    "searchItem": "AK-47 Redline",
    "maxPrice": 50
  }'
```

---

### 🖥️ **3. Test via Interface Web**

1. **Accédez à :** https://app.skinbaron-tracker.oswaaaald.be/
2. **Créez une règle de test :**
   - Cliquez sur "Create Rule"
   - Nom : "Test API"
   - Webhook Discord : `https://discord.com/api/webhooks/VOTRE_WEBHOOK`
   - Item recherché : "AK-47"
   - Prix maximum : 30€
3. **Activez temporairement l'API** (voir section suivante)
4. **Démarrez le scheduler** dans l'onglet System

---

## ⚙️ **4. Activation de l'API en Production**

Une fois que vos tests sont réussis :

### **Étape 1: Mettre à jour la configuration**
```bash
# SSH vers votre serveur Dokploy
cd /home/oswaaaald/skinbaron-alerts-sbapi

# Modifier le docker-compose.yml
nano docker-compose.yml
```

Ajoutez votre clé API dans la section environnement :
```yaml
services:
  backend:
    environment:
      - SB_API_KEY=VOTRE_VRAIE_CLE_API
```

### **Étape 2: Réactiver l'API dans le code**
```bash
# Modifier le client SkinBaron
nano backend/src/lib/sbclient.ts
```

Dans la fonction `testConnection()`, remplacez :
```typescript
async testConnection(): Promise<boolean> {
  // Temporarily skip the API test due to 415 errors
  console.log('⚠️  SkinBaron API test skipped - endpoint needs verification');
  return false; // Mark as unhealthy but don't crash the application
}
```

Par :
```typescript
async testConnection(): Promise<boolean> {
  try {
    const result = await this.search({
      search_item: 'AK-47',
      limit: 1
    });
    
    return result.success && !!result.items;
  } catch (error) {
    console.error('SkinBaron API test failed:', error);
    return false;
  }
}
```

### **Étape 3: Redéployez**
```bash
# Reconstruire et redémarrer
sudo docker-compose down
sudo docker-compose up -d --build

# Vérifier les logs
sudo docker logs skinbaron-alerts-backend -f
```

---

## 🔍 **5. Diagnostics et Validation**

### **Vérifier que l'API fonctionne :**
```bash
curl https://api.skinbaron-tracker.oswaaaald.be/api/health | jq .
```

**Résultat attendu avec API fonctionnelle :**
```json
{
  "success": true,
  "status": "healthy",  // Plus "degraded" !
  "services": {
    "database": "healthy",
    "skinbaron_api": "healthy",  // Plus "unhealthy" !
    "scheduler": "running"
  }
}
```

### **Tester une recherche manuelle :**
```bash
# Créer une règle de test
curl -X POST "https://api.skinbaron-tracker.oswaaaald.be/api/rules" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Test AK-47",
    "search_item": "AK-47",
    "max_price": 30,
    "webhook_url": "https://discord.com/api/webhooks/VOTRE_WEBHOOK",
    "enabled": true
  }'
```

### **Déclencher une vérification manuelle :**
```bash
curl -X POST "https://api.skinbaron-tracker.oswaaaald.be/api/system/run-scheduler"
```

---

## 🚨 **6. Résolution des Problèmes Courants**

### **Erreur 415 (Unsupported Media Type) :**
```
Cause : L'API SkinBaron a changé ses exigences
Solution : Vérifiez la documentation officielle SkinBaron
```

### **Erreur 401 (Unauthorized) :**
```
Cause : Clé API invalide ou expirée
Solution : Vérifiez votre clé sur le portail SkinBaron
```

### **Erreur 429 (Rate Limit) :**
```
Cause : Trop de requêtes
Solution : Augmentez l'intervalle POLL_CRON (par défaut: */5 minutes)
```

### **Pas de résultats de recherche :**
```
Cause : Critères trop restrictifs ou API en maintenance
Solution : Testez avec des critères plus larges
```

---

## 📊 **7. Monitoring Continue**

### **Logs en temps réel :**
```bash
# Backend
sudo docker logs skinbaron-alerts-backend -f

# Rechercher les erreurs API
sudo docker logs skinbaron-alerts-backend 2>&1 | grep -i "skinbaron\|error"
```

### **Statistiques système :**
```bash
curl https://api.skinbaron-tracker.oswaaaald.be/api/system/status | jq .
```

### **Alertes récentes :**
```bash
curl "https://api.skinbaron-tracker.oswaaaald.be/api/alerts?limit=10" | jq .
```

---

## ✅ **8. Checklist de Validation Finale**

Avant de considérer l'API comme pleinement fonctionnelle :

- [ ] **Script Node.js** : Tous les tests passent (6/6)
- [ ] **API Health** : Status "healthy" au lieu de "degraded"  
- [ ] **Recherche manuelle** : Retourne des résultats réels
- [ ] **Webhook Discord** : Reçoit des notifications de test
- [ ] **Scheduler** : Fonctionne sans erreurs dans les logs
- [ ] **Interface Web** : Affiche des données réelles (pas de 0 partout)

### **Commande de validation finale :**
```bash
echo "🎯 VALIDATION SKINBARON ALERTS" && \
curl -s https://api.skinbaron-tracker.oswaaaald.be/api/health | jq '.services.skinbaron_api' && \
echo "✅ Si affiche 'healthy' : API fonctionnelle !" && \
echo "❌ Si affiche 'unhealthy' : Besoin de debug"
```

---

## 🎉 **Une fois tout validé**

Votre application SkinBaron Alerts sera **100% opérationnelle** avec :
- 🔍 **Monitoring automatique** des skins CS2
- 🚨 **Alertes Discord** instantanées  
- 📊 **Interface web** avec données en temps réel
- ⚙️ **Gestion multi-utilisateurs** avec webhooks personnalisés

**Votre infrastructure sera prête pour surveiller des milliers de skins avec des notifications personnalisées !** 🎮💎