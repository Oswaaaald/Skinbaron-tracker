#!/bin/bash

# SkinBaron Alerts - Scripts de développement
# Usage: ./dev.sh [command]

set -e

# Couleurs pour les messages
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Fonctions d'affichage
print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

# Vérifier si Docker est installé
check_docker() {
    if ! command -v docker &> /dev/null; then
        print_error "Docker n'est pas installé"
        exit 1
    fi
    
    if ! command -v docker-compose &> /dev/null; then
        print_error "Docker Compose n'est pas installé"
        exit 1
    fi
}

# Fonction pour démarrer en développement avec Docker
dev_docker() {
    print_info "Démarrage en mode développement avec Docker..."
    check_docker
    
    # Créer les fichiers .env s'ils n'existent pas
    if [ ! -f backend/.env ]; then
        print_warning "Création du fichier .env backend depuis l'exemple"
        cp backend/.env.example backend/.env
    fi
    
    if [ ! -f frontend/.env.local ]; then
        print_warning "Création du fichier .env.local frontend depuis l'exemple"
        cp frontend/.env.example frontend/.env.local
    fi
    
    # Démarrer avec docker-compose
    docker-compose -f docker-compose.dev.yml up --build
}

# Fonction pour démarrer en production avec Docker
prod_docker() {
    print_info "Démarrage en mode production avec Docker..."
    check_docker
    
    # Vérifier les fichiers .env
    if [ ! -f backend/.env ]; then
        print_error "Le fichier backend/.env est requis pour la production"
        exit 1
    fi
    
    if [ ! -f frontend/.env.local ]; then
        print_error "Le fichier frontend/.env.local est requis pour la production"
        exit 1
    fi
    
    # Démarrer avec docker-compose
    docker-compose up --build
}

# Fonction pour démarrer en développement local (sans Docker)
dev_local() {
    print_info "Démarrage en mode développement local..."
    
    # Vérifier Node.js
    if ! command -v node &> /dev/null; then
        print_error "Node.js n'est pas installé"
        exit 1
    fi
    
    # Installer les dépendances si nécessaire
    if [ ! -d "backend/node_modules" ]; then
        print_info "Installation des dépendances backend..."
        cd backend && npm install && cd ..
    fi
    
    if [ ! -d "frontend/node_modules" ]; then
        print_info "Installation des dépendances frontend..."
        cd frontend && npm install && cd ..
    fi
    
    # Créer les fichiers .env s'ils n'existent pas
    if [ ! -f backend/.env ]; then
        print_warning "Création du fichier .env backend depuis l'exemple"
        cp backend/.env.example backend/.env
    fi
    
    if [ ! -f frontend/.env.local ]; then
        print_warning "Création du fichier .env.local frontend depuis l'exemple"
        cp frontend/.env.example frontend/.env.local
    fi
    
    # Démarrer le backend en arrière-plan
    print_info "Démarrage du backend sur http://localhost:8080"
    cd backend && npm run dev &
    BACKEND_PID=$!
    cd ..
    
    # Attendre que le backend démarre
    sleep 3
    
    # Démarrer le frontend
    print_info "Démarrage du frontend sur http://localhost:3000"
    cd frontend && npm run dev &
    FRONTEND_PID=$!
    cd ..
    
    print_success "Application démarrée !"
    print_info "Frontend: http://localhost:3000"
    print_info "Backend API: http://localhost:8080"
    print_info "Appuyez sur Ctrl+C pour arrêter"
    
    # Attendre et nettoyer à l'arrêt
    trap 'kill $BACKEND_PID $FRONTEND_PID 2>/dev/null; exit' INT
    wait
}

# Fonction pour construire les images Docker
build() {
    print_info "Construction des images Docker..."
    check_docker
    
    docker-compose build
    print_success "Images construites avec succès !"
}

# Fonction pour nettoyer
clean() {
    print_info "Nettoyage des containers et images..."
    check_docker
    
    docker-compose down --volumes --remove-orphans
    docker system prune -f
    print_success "Nettoyage terminé !"
}

# Fonction d'aide
show_help() {
    echo "SkinBaron Alerts - Scripts de développement"
    echo ""
    echo "Usage: ./dev.sh [command]"
    echo ""
    echo "Commands:"
    echo "  dev-docker    Démarrer en développement avec Docker"
    echo "  dev-local     Démarrer en développement local (sans Docker)"
    echo "  prod-docker   Démarrer en production avec Docker"
    echo "  build         Construire les images Docker"
    echo "  clean         Nettoyer containers et images"
    echo "  help          Afficher cette aide"
    echo ""
    echo "Exemples:"
    echo "  ./dev.sh dev-local     # Développement local"
    echo "  ./dev.sh dev-docker    # Développement avec Docker"
    echo "  ./dev.sh prod-docker   # Production avec Docker"
}

# Main
case "${1:-dev-local}" in
    "dev-docker")
        dev_docker
        ;;
    "dev-local")
        dev_local
        ;;
    "prod-docker")
        prod_docker
        ;;
    "build")
        build
        ;;
    "clean")
        clean
        ;;
    "help"|"-h"|"--help")
        show_help
        ;;
    *)
        print_error "Command inconnue: $1"
        show_help
        exit 1
        ;;
esac