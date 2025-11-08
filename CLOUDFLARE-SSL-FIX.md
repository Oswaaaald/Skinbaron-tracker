# 🌐 Configuration Cloudflare + Dokploy

## ⚠️ Problème SSL_ERROR_NO_CYPHER_OVERLAP

Cette erreur se produit quand Cloudflare (proxy orange) ne peut pas établir une connexion SSL avec votre serveur Dokploy.

## 🔧 Solutions

### **Option 1 : Mode SSL "Full" (Recommandé)**

1. **Cloudflare Dashboard** → **SSL/TLS** → **Overview**
2. Sélectionnez **"Full"** ou **"Full (strict)"**
3. Cela permet à Cloudflare de se connecter en HTTPS à votre serveur

### **Option 2 : Désactiver temporairement Cloudflare**

1. **Cloudflare Dashboard** → **DNS**
2. Cliquez sur l'icône **🟠 orange** à côté de vos domaines
3. Passez en **⚪ gris** (DNS Only)

### **Option 3 : Configuration Traefik personnalisée**

Ajouter dans vos labels Docker (docker-compose.yml) :

```yaml
services:
  frontend:
    labels:
      - "traefik.http.routers.frontend.tls=true"
      - "traefik.http.routers.frontend.tls.certresolver=letsencrypt"
      - "traefik.http.middlewares.secure-headers.headers.forceSTSHeader=true"
      - "traefik.http.middlewares.secure-headers.headers.stsSeconds=31536000"
```

## 🚀 Test rapide

Pour tester si le problème vient de Cloudflare :

```bash
# Test direct (sans Cloudflare)
curl -H "Host: app.skinbaron-tracker.oswaaaald.be" https://VOTRE_IP_SERVEUR/

# Test via Cloudflare  
curl https://app.skinbaron-tracker.oswaaaald.be/
```

## 📊 Vérifications

```bash
# Vérifier les certificats Traefik
sudo docker exec dokploy-traefik cat /etc/dokploy/traefik/dynamic/acme.json | jq .

# Vérifier les logs Traefik
sudo docker logs dokploy-traefik --tail 50

# Test SSL
openssl s_client -connect skinbaron-tracker.oswaaaald.be:443 -servername app.skinbaron-tracker.oswaaaald.be
```

## ✅ Solution Finale Recommandée

1. **Cloudflare** : Mode SSL "Full"
2. **Dokploy** : Certificats Let's Encrypt automatiques
3. **Traefik** : Configuration TLS par défaut

Cette configuration permet :
- 🛡️ Protection DDoS de Cloudflare
- ⚡ Cache et CDN global
- 🔒 SSL end-to-end
- 📊 Analytics Cloudflare

## 🔧 Commandes de Debug

```bash
# Vérifier la résolution DNS
dig app.skinbaron-tracker.oswaaaald.be

# Test SSL direct
curl -I -k https://VOTRE_IP:443

# Logs Cloudflare (si disponibles)
# Via Dashboard → Analytics → Security Events
```