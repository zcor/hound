#!/bin/bash
set -e

echo "🚀 Setting up Hound Backend in Codespaces..."

# Set default DATABASE_URL for SQLite if not set
export DATABASE_URL="${DATABASE_URL:-sqlite:///hound.db}"

# Create database if needed
if [ ! -f "hound.db" ]; then
    echo "📦 Creating database..."
    python -c "import os; from database.models import Base, create_db_engine; database_url = os.environ.get('DATABASE_URL', 'sqlite:///hound.db'); engine = create_db_engine(database_url); Base.metadata.create_all(bind=engine)"
fi

# Seed test data
if ! python -c "import os; from database.models import create_db_engine, create_db_session, Tenant; database_url = os.environ.get('DATABASE_URL', 'sqlite:///hound.db'); engine = create_db_engine(database_url); session = create_db_session(engine); exists = session.query(Tenant).filter_by(id=1).first(); session.close(); exit(0 if exists else 1)" 2>/dev/null; then
    echo "🌱 Seeding test data..."
    python scripts/seed_test_data.py
else
    echo "✓ Test data already exists"
fi

# Get Codespace info
CODESPACE_URL="https://${CODESPACE_NAME}-8000.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}"
FRONTEND_URL="https://${CODESPACE_NAME}-3000.${GITHUB_CODESPACES_PORT_FORWARDING_DOMAIN}"

echo ""
echo "✅ Setup complete!"
echo ""
echo "📋 REQUIRED: Set these environment variables in your Codespace secrets or terminal:"
echo ""
echo "export GITHUB_CLIENT_ID=\"your_client_id_here\""
echo "export GITHUB_CLIENT_SECRET=\"your_secret_here\""
echo "export JWT_SECRET_KEY=\"\$(openssl rand -hex 32)\""
echo "export FRONTEND_URL=\"${FRONTEND_URL}\""
echo "export ALLOWED_ORIGINS=\"${FRONTEND_URL}\""
echo ""
echo "📝 GitHub OAuth App Settings:"
echo "   Homepage URL: ${FRONTEND_URL}"
echo "   Callback URL: ${FRONTEND_URL}/auth/callback"
echo ""
echo "🌐 API will be available at: ${CODESPACE_URL}"
echo ""
echo "▶️  Start the server with: bash scripts/start-dev.sh"
echo ""
