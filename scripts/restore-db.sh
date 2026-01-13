#!/bin/bash
# ================================
# SkinBaron Tracker - Restore Script
# ================================
# Restaure la base de données depuis un backup
# Usage: ./scripts/restore-db.sh <backup-file.tar.gz>

set -e

# Configuration
VOLUME_NAME="skinbaron_backend_data"
BACKUP_DIR="/var/backups/skinbaron"

# Couleurs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Vérifier l'argument
if [ -z "$1" ]; then
    log_error "Usage: $0 <backup-file.tar.gz>"
    log_info "Backups disponibles :"
    ls -lh "$BACKUP_DIR"/alerts-*.tar.gz 2>/dev/null || log_warn "Aucun backup trouvé"
    exit 1
fi

BACKUP_FILE="$1"

# Vérifier que le fichier existe
if [ ! -f "$BACKUP_FILE" ]; then
    # Essayer dans le dossier de backup
    if [ -f "$BACKUP_DIR/$BACKUP_FILE" ]; then
        BACKUP_FILE="$BACKUP_DIR/$BACKUP_FILE"
    else
        log_error "Fichier $BACKUP_FILE introuvable !"
        exit 1
    fi
fi

log_warn "⚠️  ATTENTION : Cette opération va ÉCRASER les données actuelles !"
read -p "Êtes-vous sûr ? (oui/non) : " CONFIRM

if [ "$CONFIRM" != "oui" ]; then
    log_info "Restauration annulée"
    exit 0
fi

# Vérifier que le volume existe
if ! docker volume inspect "$VOLUME_NAME" &>/dev/null; then
    log_error "Volume $VOLUME_NAME n'existe pas !"
    exit 1
fi

# Arrêter le backend pour éviter les corruptions
log_info "Arrêt du backend..."
docker stop skinbaron-tracker-backend 2>/dev/null || log_warn "Backend déjà arrêté"

# Restaurer le backup
log_info "Restauration du backup $BACKUP_FILE..."
docker run --rm \
    -v "$VOLUME_NAME":/data \
    -v "$(dirname $BACKUP_FILE)":/backup:ro \
    alpine:latest \
    sh -c "rm -rf /data/* && tar xzf /backup/$(basename $BACKUP_FILE) -C /data"

if [ $? -eq 0 ]; then
    log_info "✅ Backup restauré avec succès !"
else
    log_error "❌ Échec de la restauration !"
    exit 1
fi

# Redémarrer le backend
log_info "Redémarrage du backend..."
docker start skinbaron-tracker-backend

log_info "✅ Restauration terminée !"
