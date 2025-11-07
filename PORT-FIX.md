# 🚨 SOLUTION : Conflit de port Dokploy

## Problème rencontré
```
Error: Bind for 0.0.0.0:8080 failed: port is already allocated
```

## ✅ Solution

Le port 8080 est déjà utilisé sur le serveur Dokploy. Nous avons modifié la configuration pour utiliser des ports alternatifs.

### 1. Configurer les variables d'environnement dans Dokploy

Aller dans votre application Dokploy → Variables d'environnement et ajouter :

```bash
BACKEND_PORT=3001
FRONTEND_PORT=3002
CORS_ORIGIN=*
NEXT_PUBLIC_API_URL=http://localhost:3001
```

### 2. Ou utiliser le fichier .env.dokploy

Copier le contenu de `.env.dokploy` dans les variables d'environnement Dokploy :

```bash
# Copier le contenu de ce fichier :
cat .env.dokploy
```

### 3. Redéployer

Une fois les variables configurées, redéployer l'application :

1. Aller sur Dokploy
2. Sélectionner votre application  
3. Cliquer "Redeploy"
4. Les containers utiliseront maintenant les ports 3001 et 3002

### 4. Vérifier le déploiement

```bash
# Vérifier que l'API répond sur le nouveau port
curl http://votre-serveur:3001/api/health

# Vérifier le frontend
curl http://votre-serveur:3002
```

### 5. Configuration des domaines Dokploy

Dans Dokploy, configurer :

- **Backend** : Port 3001 → votre-api.domaine.com
- **Frontend** : Port 3002 → votre-app.domaine.com

## 📝 Notes importantes

- Les containers utilisent toujours les ports 8080 et 3000 **à l'intérieur**
- Seuls les ports **externes** changent (3001 et 3002)
- Cette configuration évite les conflits avec d'autres services sur le serveur Dokploy

## 🔄 Après le déploiement

Mettre à jour la variable `NEXT_PUBLIC_API_URL` avec votre vraie URL :

```bash
NEXT_PUBLIC_API_URL=https://votre-api.domaine.com
```