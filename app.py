# ========# app.py - Backend da aplicação Web com Flask

import os
import json
import sqlite3
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Optional, Tuple, Generator
from dataclasses import dataclass, asdict
import asyncio
from functools import wraps
import queue
import threading
import time
import yaml
import hashlib
import secrets

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, Response, stream_with_context, flash
from flask_cors import CORS
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from openai import OpenAI
from duckduckgo_search import DDGS
from duckduckgo_search.exceptions import RatelimitException, TimeoutException
import markdown
from dotenv import load_dotenv

# Carrega variáveis de ambiente
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'your-secret-key-here')
app.config['DATABASE'] = 'chat_sessions.db'
app.config['USERS_FILE'] = 'users.yaml'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)

CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# Configuração do Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Por favor, faça login para acessar esta página.'

# ========== MODELOS DE DADOS ==========

class User(UserMixin):
    """Modelo de usuário para Flask-Login"""
    def __init__(self, username, email, role='user', active=True):
        self.id = username
        self.username = username
        self.email = email
        self.role = role
        self.active = active
    
    def is_admin(self):
        return self.role == 'admin'
    
    def is_active(self):
        return self.active

@dataclass
class SearchResult:
    """Estrutura para armazenar resultados de busca"""
    title: str
    snippet: str
    url: str
    timestamp: str = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

@dataclass
class Message:
    """Estrutura para mensagens do chat"""
    id: str
    session_id: str
    role: str  # 'user', 'assistant', 'system'
    content: str
    timestamp: str
    search_results: List[Dict] = None
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()

@dataclass
class ChatSession:
    """Estrutura para sessões de chat"""
    id: str
    user_id: str  # Adicionando o campo user_id
    title: str
    created_at: str
    updated_at: str
    message_count: int = 0
    
# ========== GERENCIAMENTO DE USUÁRIOS ==========

class UserManager:
    """Gerenciador de usuários com arquivo YAML"""
    
    def __init__(self, users_file: str):
        self.users_file = users_file
        self.ensure_users_file()
    
    def ensure_users_file(self):
        """Cria arquivo de usuários se não existir"""
        if not os.path.exists(self.users_file):
            default_users = {
                'users': {
                    'admin': {
                        'email': 'admin@example.com',
                        'password': generate_password_hash('admin123'),
                        'role': 'admin',
                        'active': True,
                        'created_at': datetime.now().isoformat()
                    }
                }
            }
            self.save_users(default_users)
    
    def load_users(self) -> Dict:
        """Carrega usuários do arquivo YAML"""
        try:
            with open(self.users_file, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f) or {'users': {}}
        except Exception as e:
            print(f"Erro ao carregar usuários: {e}")
            return {'users': {}}
    
    def save_users(self, data: Dict):
        """Salva usuários no arquivo YAML"""
        try:
            with open(self.users_file, 'w', encoding='utf-8') as f:
                yaml.dump(data, f, allow_unicode=True, default_flow_style=False)
        except Exception as e:
            print(f"Erro ao salvar usuários: {e}")
    
    def get_user(self, username: str) -> Optional[User]:
        """Busca um usuário pelo username"""
        data = self.load_users()
        if username in data.get('users', {}):
            user_data = data['users'][username]
            return User(
                username=username,
                email=user_data.get('email'),
                role=user_data.get('role', 'user'),
                active=user_data.get('active', True)
            )
        return None
    
    def verify_password(self, username: str, password: str) -> bool:
        """Verifica a senha de um usuário"""
        data = self.load_users()
        if username in data.get('users', {}):
            stored_hash = data['users'][username].get('password')
            return check_password_hash(stored_hash, password)
        return False
    
    def create_user(self, username: str, email: str, password: str, role: str = 'user') -> bool:
        """Cria um novo usuário"""
        data = self.load_users()
        if username in data.get('users', {}):
            return False  # Usuário já existe
        
        data.setdefault('users', {})[username] = {
            'email': email,
            'password': generate_password_hash(password),
            'role': role,
            'active': True,
            'created_at': datetime.now().isoformat()
        }
        self.save_users(data)
        return True
    
    def update_user(self, username: str, updates: Dict) -> bool:
        """Atualiza dados de um usuário"""
        data = self.load_users()
        if username not in data.get('users', {}):
            return False
        
        user_data = data['users'][username]
        for key, value in updates.items():
            if key == 'password' and value:
                user_data[key] = generate_password_hash(value)
            elif key != 'password':
                user_data[key] = value
        
        user_data['updated_at'] = datetime.now().isoformat()
        self.save_users(data)
        return True
    
    def delete_user(self, username: str) -> bool:
        """Remove um usuário"""
        data = self.load_users()
        if username in data.get('users', {}):
            del data['users'][username]
            self.save_users(data)
            return True
        return False
    
    def list_users(self) -> List[Dict]:
        """Lista todos os usuários"""
        data = self.load_users()
        users = []
        for username, user_data in data.get('users', {}).items():
            users.append({
                'username': username,
                'email': user_data.get('email'),
                'role': user_data.get('role', 'user'),
                'active': user_data.get('active', True),
                'created_at': user_data.get('created_at'),
                'updated_at': user_data.get('updated_at')
            })
        return users

# ========== DATABASE ==========

class Database:
    """Gerenciador de banco de dados SQLite"""
    
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.init_db()
    
    def init_db(self):
        """Inicializa as tabelas do banco de dados"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS sessions (
                    id TEXT PRIMARY KEY,
                    user_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    message_count INTEGER DEFAULT 0,
                    FOREIGN KEY (user_id) REFERENCES users(username)
                )
            ''')
            
            conn.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    id TEXT PRIMARY KEY,
                    session_id TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    search_results TEXT,
                    FOREIGN KEY (session_id) REFERENCES sessions(id),
                    FOREIGN KEY (user_id) REFERENCES users(username)
                )
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_messages_session 
                ON messages(session_id)
            ''')
            
            conn.execute('''
                CREATE INDEX IF NOT EXISTS idx_sessions_user 
                ON sessions(user_id)
            ''')
            
            conn.commit()
    
    def create_session(self, user_id: str, title: str = "Nova Conversa") -> ChatSession:
        """Cria uma nova sessão de chat"""
        session = ChatSession(
            id=str(uuid.uuid4()),
            user_id=user_id,  # Adicionando user_id aqui
            title=title,
            created_at=datetime.now().isoformat(),
            updated_at=datetime.now().isoformat()
        )
        
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                INSERT INTO sessions (id, user_id, title, created_at, updated_at, message_count)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (session.id, user_id, session.title, session.created_at, 
                  session.updated_at, session.message_count))
            conn.commit()
        
        return session
    
    def get_session(self, session_id: str, user_id: str = None) -> Optional[ChatSession]:
        """Recupera uma sessão pelo ID (com verificação de usuário opcional)"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            query = 'SELECT * FROM sessions WHERE id = ?'
            params = [session_id]
            
            if user_id:
                query += ' AND user_id = ?'
                params.append(user_id)
            
            cursor = conn.execute(query, params)
            
            row = cursor.fetchone()
            if row:
                return ChatSession(**dict(row))
            return None
    
    def get_user_sessions(self, user_id: str) -> List[ChatSession]:
        """Recupera todas as sessões de um usuário"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM sessions 
                WHERE user_id = ?
                ORDER BY updated_at DESC
            ''', (user_id,))
            
            return [ChatSession(**dict(row)) for row in cursor.fetchall()]
    
    def get_all_sessions(self) -> List[ChatSession]:
        """Recupera todas as sessões (admin only)"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute('''
                SELECT * FROM sessions 
                ORDER BY updated_at DESC
            ''')
            
            return [ChatSession(**dict(row)) for row in cursor.fetchall()]
    
    def update_session_title(self, session_id: str, title: str):
        """Atualiza o título de uma sessão"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                UPDATE sessions 
                SET title = ?, updated_at = ?
                WHERE id = ?
            ''', (title, datetime.now().isoformat(), session_id))
            conn.commit()
    
    def delete_session(self, session_id: str):
        """Deleta uma sessão e suas mensagens"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('DELETE FROM messages WHERE session_id = ?', (session_id,))
            conn.execute('DELETE FROM sessions WHERE id = ?', (session_id,))
            conn.commit()
    
    def add_message(self, message: Message, user_id: str):
        """Adiciona uma mensagem ao banco"""
        with sqlite3.connect(self.db_path) as conn:
            search_results_json = json.dumps(message.search_results) if message.search_results else None
            
            conn.execute('''
                INSERT INTO messages (id, session_id, user_id, role, content, timestamp, search_results)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (message.id, message.session_id, user_id, message.role, 
                  message.content, message.timestamp, search_results_json))
            
            # Atualiza contador de mensagens e timestamp da sessão
            conn.execute('''
                UPDATE sessions 
                SET message_count = message_count + 1, updated_at = ?
                WHERE id = ?
            ''', (datetime.now().isoformat(), message.session_id))
            
            conn.commit()
    
    def get_messages(self, session_id: str, user_id: str = None) -> List[Message]:
        """Recupera todas as mensagens de uma sessão"""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            
            # Verifica se o usuário tem acesso à sessão
            if user_id:
                session = self.get_session(session_id, user_id)
                if not session:
                    return []
            
            cursor = conn.execute('''
                SELECT id, session_id, role, content, timestamp, search_results 
                FROM messages 
                WHERE session_id = ? 
                ORDER BY timestamp ASC
            ''', (session_id,))
            
            messages = []
            for row in cursor.fetchall():
                data = dict(row)
                if data.get('search_results'):
                    data['search_results'] = json.loads(data['search_results'])
                messages.append(Message(**data))
            
            return messages

# ========== AI SEARCH BOT ==========

class AISearchBot:
    """Bot de busca inteligente usando DeepSeek e DuckDuckGo"""
    
    def __init__(self, deepseek_api_key: str, db: Database):
        self.client = OpenAI(
            api_key=deepseek_api_key,
            base_url="https://api.deepseek.com"
        )
        self.ddgs = DDGS()
        self.db = db
    
    def search_web(self, query: str, max_results: int = 5) -> List[SearchResult]:
        """Busca informações na web usando DuckDuckGo"""
        try:
            results = self.ddgs.text(
                keywords=query,
                region='pt-br',
                safesearch='moderate',
                max_results=max_results
            )
            
            search_results = []
            for r in results:
                search_results.append(SearchResult(
                    title=r.get('title', ''),
                    snippet=r.get('body', ''),
                    url=r.get('href', '')
                ))
            
            return search_results
            
        except (RatelimitException, TimeoutException) as e:
            print(f"Erro na busca: {e}")
            return []
    
    def extract_search_intent(self, user_query: str) -> Optional[str]:
        """Extrai a intenção de busca da pergunta do usuário"""
        try:
            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {
                        "role": "system",
                        "content": """Você é um assistente especializado em extrair termos de busca.
                        Analise a pergunta do usuário e:
                        1. Se a pergunta requer informações atuais da web, extraia os melhores termos de busca
                        2. Se a pergunta NÃO requer busca (perguntas gerais, matemática, código), responda com "NO_SEARCH"
                        3. Retorne APENAS os termos de busca ou "NO_SEARCH", nada mais."""
                    },
                    {
                        "role": "user",
                        "content": user_query
                    }
                ],
                temperature=0.3,
                max_tokens=100
            )
            
            search_terms = response.choices[0].message.content.strip()
            
            if search_terms == "NO_SEARCH":
                return None
                
            return search_terms
            
        except Exception as e:
            print(f"Erro ao extrair termos de busca: {e}")
            return None
    
    def generate_response_stream(self, session_id: str, user_query: str, search_results: List[SearchResult] = None):
        """Gera resposta em streaming"""
        try:
            # Recupera histórico da sessão
            messages = self.db.get_messages(session_id)
            
            # Prepara mensagens para o contexto
            context_messages = [
                {
                    "role": "system",
                    "content": """Você é um assistente de busca inteligente que combina conhecimento geral com informações atuais da web.
                    
                    Diretrizes:
                    1. Use os resultados de busca quando disponíveis para fornecer informações atualizadas
                    2. Quando citar informações dos resultados de busca, use citações numeradas como [1], [2], etc.
                    3. As citações devem corresponder à ordem dos resultados fornecidos
                    4. Seja preciso, conciso e útil
                    5. Se não houver resultados de busca relevantes, use seu conhecimento geral
                    6. Sempre forneça respostas em português brasileiro
                    7. Use formatação Markdown para melhor legibilidade
                    8. Ao final da resposta que usa resultados de busca, adicione uma seção "Fontes:" listando as citações"""
                }
            ]
            
            # Adiciona histórico (últimas 10 mensagens)
            for msg in messages[-10:]:
                if msg.role in ['user', 'assistant']:
                    context_messages.append({
                        "role": msg.role,
                        "content": msg.content
                    })
            
            # Adiciona contexto de busca se disponível
            if search_results:
                search_context = self._format_search_results_with_numbers(search_results)
                context_messages.append({
                    "role": "system",
                    "content": f"Informações atuais da web (use citações [1], [2], etc):\n{search_context}"
                })
            
            # Adiciona pergunta atual
            context_messages.append({
                "role": "user",
                "content": user_query
            })
            
            # Gera resposta em streaming
            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=context_messages,
                temperature=0.7,
                max_tokens=2000,
                stream=True
            )
            
            for chunk in response:
                if chunk.choices[0].delta.content:
                    yield chunk.choices[0].delta.content
                    
        except Exception as e:
            yield f"\n\n❌ Erro ao gerar resposta: {str(e)}"
    
    def _format_search_results_with_numbers(self, results: List[SearchResult]) -> str:
        """Formata resultados de busca com números para citação"""
        if not results:
            return "Nenhum resultado encontrado."
            
        formatted = "Resultados da busca:\n\n"
        for i, result in enumerate(results, 1):
            formatted += f"[{i}] **{result.title}**\n"
            formatted += f"    {result.snippet}\n"
            formatted += f"    URL: {result.url}\n\n"
            
        return formatted
    
    def generate_session_title(self, first_message: str) -> str:
        """Gera um título para a sessão baseado na primeira mensagem"""
        try:
            response = self.client.chat.completions.create(
                model="deepseek-chat",
                messages=[
                    {
                        "role": "system",
                        "content": "Gere um título curto (máximo 50 caracteres) para uma conversa que começa com a seguinte mensagem. Retorne APENAS o título, sem aspas ou formatação adicional."
                    },
                    {
                        "role": "user",
                        "content": first_message
                    }
                ],
                temperature=0.7,
                max_tokens=50
            )
            
            return response.choices[0].message.content.strip()[:50]
            
        except:
            return "Nova Conversa"

# ========== INICIALIZAÇÃO ==========

db = Database(app.config['DATABASE'])
user_manager = UserManager(app.config['USERS_FILE'])
bot = AISearchBot(os.getenv('DEEPSEEK_API_KEY'), db)

# ========== FLASK-LOGIN SETUP ==========

@login_manager.user_loader
def load_user(username):
    return user_manager.get_user(username)

# ========== DECORADORES ==========

def admin_required(f):
    """Decorator para rotas que requerem privilégios de admin"""
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin():
            return jsonify({'error': 'Acesso negado. Privilégios de administrador necessários.'}), 403
        return f(*args, **kwargs)
    return decorated_function

# ========== ROTAS DE AUTENTICAÇÃO ==========

@app.route('/login')
def login():
    """Página de login"""
    return render_template('login.html')

@app.route('/api/auth/login', methods=['POST'])
def api_login():
    """API de login"""
    data = request.json
    username = data.get('username')
    password = data.get('password')
    remember = data.get('remember', False)
    
    if not username or not password:
        return jsonify({'error': 'Username e senha são obrigatórios'}), 400
    
    user = user_manager.get_user(username)
    if user and user_manager.verify_password(username, password):
        if not user.is_active():
            return jsonify({'error': 'Conta desativada'}), 403
        
        login_user(user, remember=remember)
        return jsonify({
            'success': True,
            'user': {
                'username': user.username,
                'email': user.email,
                'role': user.role
            }
        })
    
    return jsonify({'error': 'Credenciais inválidas'}), 401

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def api_logout():
    """API de logout"""
    logout_user()
    return jsonify({'success': True})

@app.route('/api/auth/me', methods=['GET'])
@login_required
def get_current_user():
    """Retorna informações do usuário atual"""
    return jsonify({
        'username': current_user.username,
        'email': current_user.email,
        'role': current_user.role
    })

# ========== ROTAS ADMINISTRATIVAS ==========

@app.route('/admin')
@admin_required
def admin_panel():
    """Painel administrativo"""
    return render_template('admin.html')

@app.route('/api/admin/users', methods=['GET'])
@admin_required
def list_users():
    """Lista todos os usuários"""
    users = user_manager.list_users()
    return jsonify(users)

@app.route('/api/admin/users', methods=['POST'])
@admin_required
def create_user():
    """Cria um novo usuário"""
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    role = data.get('role', 'user')
    
    if not all([username, email, password]):
        return jsonify({'error': 'Todos os campos são obrigatórios'}), 400
    
    if user_manager.create_user(username, email, password, role):
        return jsonify({'success': True, 'message': 'Usuário criado com sucesso'})
    else:
        return jsonify({'error': 'Usuário já existe'}), 409

@app.route('/api/admin/users/<username>', methods=['PUT'])
@admin_required
def update_user(username):
    """Atualiza um usuário"""
    data = request.json
    
    # Não permite alterar o próprio role
    if username == current_user.username and 'role' in data:
        return jsonify({'error': 'Você não pode alterar seu próprio role'}), 403
    
    if user_manager.update_user(username, data):
        return jsonify({'success': True, 'message': 'Usuário atualizado com sucesso'})
    else:
        return jsonify({'error': 'Usuário não encontrado'}), 404

@app.route('/api/admin/users/<username>', methods=['DELETE'])
@admin_required
def delete_user(username):
    """Remove um usuário"""
    # Não permite deletar a si mesmo
    if username == current_user.username:
        return jsonify({'error': 'Você não pode deletar sua própria conta'}), 403
    
    if user_manager.delete_user(username):
        return jsonify({'success': True, 'message': 'Usuário removido com sucesso'})
    else:
        return jsonify({'error': 'Usuário não encontrado'}), 404

@app.route('/api/admin/stats', methods=['GET'])
@admin_required
def get_admin_stats():
    """Retorna estatísticas do sistema"""
    with sqlite3.connect(app.config['DATABASE']) as conn:
        # Total de usuários
        users_count = len(user_manager.list_users())
        
        # Total de sessões
        sessions_count = conn.execute('SELECT COUNT(*) FROM sessions').fetchone()[0]
        
        # Total de mensagens
        messages_count = conn.execute('SELECT COUNT(*) FROM messages').fetchone()[0]
        
        # Sessões por usuário
        sessions_by_user = conn.execute('''
            SELECT user_id, COUNT(*) as count 
            FROM sessions 
            GROUP BY user_id
        ''').fetchall()
        
        # Atividade recente
        recent_activity = conn.execute('''
            SELECT s.user_id, s.title, s.updated_at 
            FROM sessions s 
            ORDER BY s.updated_at DESC 
            LIMIT 10
        ''').fetchall()
        
        return jsonify({
            'users_count': users_count,
            'sessions_count': sessions_count,
            'messages_count': messages_count,
            'sessions_by_user': [{'user': row[0], 'count': row[1]} for row in sessions_by_user],
            'recent_activity': [{'user': row[0], 'title': row[1], 'updated_at': row[2]} for row in recent_activity]
        })

# ========== ROTAS PROTEGIDAS (CHAT) ==========

@app.route('/')
def index():
    """Página principal - redireciona para login se não autenticado"""
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/api/sessions', methods=['GET'])
@login_required
def get_sessions():
    """Retorna todas as sessões do usuário atual"""
    sessions = db.get_user_sessions(current_user.id)
    return jsonify([asdict(s) for s in sessions])

@app.route('/api/sessions', methods=['POST'])
@login_required
def create_session():
    """Cria uma nova sessão"""
    data = request.json
    title = data.get('title', 'Nova Conversa')
    session = db.create_session(current_user.id, title)
    return jsonify(asdict(session))

@app.route('/api/sessions/<session_id>', methods=['GET'])
@login_required
def get_session(session_id):
    """Retorna uma sessão específica com suas mensagens"""
    session = db.get_session(session_id, current_user.id)
    if not session:
        return jsonify({'error': 'Sessão não encontrada ou sem permissão'}), 404
    
    messages = db.get_messages(session_id, current_user.id)
    
    return jsonify({
        'session': asdict(session),
        'messages': [asdict(m) for m in messages]
    })

@app.route('/api/sessions/<session_id>', methods=['DELETE'])
@login_required
def delete_session(session_id):
    """Deleta uma sessão"""
    session = db.get_session(session_id, current_user.id)
    if not session:
        return jsonify({'error': 'Sessão não encontrada ou sem permissão'}), 404
    
    db.delete_session(session_id)
    return jsonify({'success': True})

@app.route('/api/sessions/<session_id>/export/<format>', methods=['GET'])
@login_required
def export_session(session_id, format):
    """Exporta uma sessão em diferentes formatos"""
    session = db.get_session(session_id, current_user.id)
    if not session:
        return jsonify({'error': 'Sessão não encontrada ou sem permissão'}), 404
    
    messages = db.get_messages(session_id, current_user.id)
    
    if format == 'markdown':
        # Gerar Markdown
        content = f"# {session.title}\n\n"
        content += f"*Exportado em {datetime.now().strftime('%d/%m/%Y %H:%M')}*\n\n---\n\n"
        
        for msg in messages:
            if msg.role == 'user':
                content += f"### 👤 Você\n{msg.content}\n\n"
            else:
                content += f"### 🤖 AI Assistant\n{msg.content}\n\n"
                
                if msg.search_results:
                    content += "**Fontes:**\n"
                    for i, result in enumerate(msg.search_results, 1):
                        content += f"- [{i}] [{result['title']}]({result['url']})\n"
                    content += "\n"
            
            content += f"*{datetime.fromisoformat(msg.timestamp).strftime('%H:%M')}*\n\n---\n\n"
        
        response = Response(content, mimetype='text/markdown')
        response.headers['Content-Disposition'] = f'attachment; filename="{session.title}.md"'
        return response
    
    elif format == 'pdf':
        # Para PDF, vamos usar uma biblioteca simples
        try:
            from reportlab.lib.pagesizes import letter, A4
            from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import inch
            from reportlab.lib.enums import TA_CENTER, TA_JUSTIFY
            import io
            
            buffer = io.BytesIO()
            doc = SimpleDocTemplate(buffer, pagesize=A4)
            story = []
            styles = getSampleStyleSheet()
            
            # Título
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                textColor='#1e40af',
                alignment=TA_CENTER,
                spaceAfter=30
            )
            story.append(Paragraph(session.title, title_style))
            story.append(Spacer(1, 0.2*inch))
            
            # Mensagens
            for msg in messages:
                if msg.role == 'user':
                    story.append(Paragraph("<b>Você:</b>", styles['Heading3']))
                    story.append(Paragraph(msg.content.replace('\n', '<br/>'), styles['Normal']))
                else:
                    story.append(Paragraph("<b>AI Assistant:</b>", styles['Heading3']))
                    # Converter markdown para HTML básico para PDF
                    content = msg.content.replace('\n', '<br/>')
                    content = content.replace('**', '<b>').replace('**', '</b>')
                    content = content.replace('*', '<i>').replace('*', '</i>')
                    story.append(Paragraph(content, styles['Normal']))
                
                story.append(Spacer(1, 0.2*inch))
            
            doc.build(story)
            buffer.seek(0)
            
            response = Response(buffer.read(), mimetype='application/pdf')
            response.headers['Content-Disposition'] = f'attachment; filename="{session.title}.pdf"'
            return response
            
        except ImportError:
            return jsonify({'error': 'PDF export não disponível. Instale: pip install reportlab'}), 503
    
    else:
        return jsonify({'error': 'Formato não suportado'}), 400

# ========== SSE (SERVER-SENT EVENTS) ==========

def generate_sse_message(event: str, data: Dict, id: str = None) -> str:
    """Formata uma mensagem SSE"""
    message = f"event: {event}\n"
    if id:
        message += f"id: {id}\n"
    message += f"data: {json.dumps(data)}\n\n"
    return message

@app.route('/api/chat/stream', methods=['POST'])
@login_required
def chat_stream():
    """Endpoint SSE para streaming de chat"""
    data = request.json
    session_id = data.get('session_id')
    user_message = data.get('message')
    
    if not session_id or not user_message:
        return jsonify({'error': 'Dados inválidos'}), 400
    
    # Verifica se a sessão existe e pertence ao usuário
    session = db.get_session(session_id, current_user.id)
    if not session:
        return jsonify({'error': 'Sessão não encontrada ou sem permissão'}), 404
    
    def generate():
        try:
            # Yield inicial para estabelecer conexão SSE
            yield generate_sse_message('connected', {'status': 'Conexão estabelecida'})
            
            # Salva mensagem do usuário
            user_msg = Message(
                id=str(uuid.uuid4()),
                session_id=session_id,
                role='user',
                content=user_message,
                timestamp=datetime.now().isoformat()
            )
            db.add_message(user_msg, current_user.id)
            
            # Envia confirmação da mensagem do usuário
            yield generate_sse_message('user_message', asdict(user_msg))
            
            # Se for a primeira mensagem, gera título para a sessão
            if session.message_count == 0:
                yield generate_sse_message('status', {'message': 'Gerando título da conversa...'})
                new_title = bot.generate_session_title(user_message)
                db.update_session_title(session_id, new_title)
                yield generate_sse_message('session_title_updated', {
                    'session_id': session_id,
                    'title': new_title
                })
            
            # Extrai intenção de busca
            yield generate_sse_message('status', {'message': 'Analisando sua pergunta...'})
            search_terms = bot.extract_search_intent(user_message)
            
            search_results = []
            if search_terms:
                # Realiza busca
                yield generate_sse_message('status', {'message': f'Buscando: {search_terms}'})
                search_results = bot.search_web(search_terms)
                
                if search_results:
                    yield generate_sse_message('search_results', {
                        'query': search_terms,
                        'results': [asdict(r) for r in search_results]
                    })
            
            # Inicia streaming da resposta
            yield generate_sse_message('status', {'message': 'Gerando resposta...'})
            yield generate_sse_message('response_start', {})
            
            full_response = ""
            assistant_msg_id = str(uuid.uuid4())
            
            # Stream da resposta do bot
            for chunk in bot.generate_response_stream(session_id, user_message, search_results):
                full_response += chunk
                yield generate_sse_message('response_chunk', {
                    'chunk': chunk,
                    'message_id': assistant_msg_id
                })
            
            # Salva resposta completa
            assistant_msg = Message(
                id=assistant_msg_id,
                session_id=session_id,
                role='assistant',
                content=full_response,
                timestamp=datetime.now().isoformat(),
                search_results=[asdict(r) for r in search_results] if search_results else None
            )
            db.add_message(assistant_msg, current_user.id)
            
            # Envia mensagem final
            yield generate_sse_message('response_end', {
                'message': asdict(assistant_msg)
            })
            
            # Evento de conclusão
            yield generate_sse_message('done', {'status': 'Concluído'})
            
        except Exception as e:
            print(f"Erro no streaming: {str(e)}")
            yield generate_sse_message('error', {
                'message': f'Erro ao processar mensagem: {str(e)}'
            })
    
    return Response(
        stream_with_context(generate()),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',  # Desabilita buffering no nginx
            'Connection': 'keep-alive'
        }
    )

@app.route('/api/chat/stream/<session_id>/messages', methods=['GET'])
def get_messages_stream(session_id):
    """Endpoint SSE para receber atualizações de mensagens em tempo real"""
    
    def generate():
        # Queue para mensagens
        message_queue = queue.Queue()
        
        # Flag para controlar o loop
        should_continue = threading.Event()
        should_continue.set()
        
        # Envia heartbeat periodicamente para manter conexão viva
        def heartbeat():
            while should_continue.is_set():
                try:
                    message_queue.put(('heartbeat', {'timestamp': datetime.now().isoformat()}))
                    time.sleep(30)  # Heartbeat a cada 30 segundos
                except:
                    break
        
        heartbeat_thread = threading.Thread(target=heartbeat)
        heartbeat_thread.daemon = True
        heartbeat_thread.start()
        
        try:
            # Envia estado inicial
            yield generate_sse_message('connected', {
                'session_id': session_id,
                'timestamp': datetime.now().isoformat()
            })
            
            # Loop principal
            while should_continue.is_set():
                try:
                    # Espera por mensagens com timeout
                    event, data = message_queue.get(timeout=1.0)
                    yield generate_sse_message(event, data)
                except queue.Empty:
                    continue
                except GeneratorExit:
                    break
                    
        finally:
            should_continue.clear()
    
    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control': 'no-cache',
            'X-Accel-Buffering': 'no',
            'Connection': 'keep-alive'
        }
    )

# ========== HEALTH CHECK E STATUS ==========

@app.route('/api/health', methods=['GET'])
def health_check():
    """Verifica o status da aplicação"""
    try:
        # Testa conexão com banco de dados
        with sqlite3.connect(app.config['DATABASE']) as conn:
            conn.execute('SELECT 1')
        
        # Testa API key do DeepSeek
        api_key_status = 'configured' if os.getenv('DEEPSEEK_API_KEY') else 'missing'
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.now().isoformat(),
            'database': 'connected',
            'deepseek_api': api_key_status,
            'version': '1.0.0'
        })
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

# ========== TRATAMENTO DE ERROS ==========

@app.errorhandler(404)
def not_found(error):
    """Tratamento para rotas não encontradas"""
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Endpoint não encontrado'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    """Tratamento para erros internos"""
    return jsonify({
        'error': 'Erro interno do servidor',
        'message': str(error)
    }), 500

# ========== MIDDLEWARE PARA SSE ==========

@app.after_request
def after_request(response):
    """Adiciona headers necessários para SSE"""
    if 'text/event-stream' in response.headers.get('Content-Type', ''):
        response.headers['X-Accel-Buffering'] = 'no'
        response.headers['Cache-Control'] = 'no-cache, no-transform'
        response.headers['Connection'] = 'keep-alive'
    return response

# ========== WEBSOCKET EVENTS ==========

@socketio.on('connect')
def handle_connect():
    """Cliente conectado"""
    print(f"Cliente conectado: {request.sid}")
    emit('connected', {'data': 'Conectado ao servidor'})

@socketio.on('disconnect')
def handle_disconnect():
    """Cliente desconectado"""
    print(f"Cliente desconectado: {request.sid}")

@socketio.on('join_session')
def handle_join_session(data):
    """Cliente entra em uma sessão"""
    session_id = data.get('session_id')
    if session_id:
        join_room(session_id)
        emit('joined_session', {'session_id': session_id})

@socketio.on('leave_session')
def handle_leave_session(data):
    """Cliente sai de uma sessão"""
    session_id = data.get('session_id')
    if session_id:
        leave_room(session_id)

@socketio.on('send_message')
@login_required
def handle_message(data):
    """Processa mensagem do usuário"""
    session_id = data.get('session_id')
    user_message = data.get('message')
    force_search = data.get('force_search', False)
    
    if not session_id or not user_message:
        emit('error', {'message': 'Dados inválidos'})
        return
    
    # Verifica se a sessão existe e pertence ao usuário
    session = db.get_session(session_id, current_user.id)
    if not session:
        emit('error', {'message': 'Sessão não encontrada ou sem permissão'})
        return
    
    # Salva mensagem do usuário
    user_msg = Message(
        id=str(uuid.uuid4()),
        session_id=session_id,
        role='user',
        content=user_message,
        timestamp=datetime.now().isoformat()
    )
    db.add_message(user_msg, current_user.id)
    
    # Se for a primeira mensagem, gera título para a sessão
    if session.message_count == 0:
        new_title = bot.generate_session_title(user_message)
        db.update_session_title(session_id, new_title)
        emit('session_title_updated', {
            'session_id': session_id,
            'title': new_title
        }, room=session_id)
    
    # Emite confirmação da mensagem do usuário
    emit('message_received', asdict(user_msg), room=session_id)
    
    # Extrai intenção de busca ou força busca
    emit('status', {'message': 'Analisando sua pergunta...'}, room=session_id)
    
    if force_search:
        search_terms = user_message  # Usa a mensagem inteira como termo de busca
    else:
        search_terms = bot.extract_search_intent(user_message)
    
    search_results = []
    if search_terms:
        # Realiza busca
        emit('status', {'message': f'Buscando: {search_terms}'}, room=session_id)
        search_results = bot.search_web(search_terms)
        
        if search_results:
            emit('search_results', {
                'query': search_terms,
                'results': [asdict(r) for r in search_results]
            }, room=session_id)
    
    # Inicia streaming da resposta
    emit('status', {'message': 'Gerando resposta...'}, room=session_id)
    emit('response_start', {}, room=session_id)
    
    full_response = ""
    assistant_msg_id = str(uuid.uuid4())
    
    # Stream da resposta
    for chunk in bot.generate_response_stream(session_id, user_message, search_results):
        full_response += chunk
        emit('response_chunk', {
            'chunk': chunk,
            'message_id': assistant_msg_id
        }, room=session_id)
    
    # Salva resposta completa
    assistant_msg = Message(
        id=assistant_msg_id,
        session_id=session_id,
        role='assistant',
        content=full_response,
        timestamp=datetime.now().isoformat(),
        search_results=[asdict(r) for r in search_results] if search_results else None
    )
    db.add_message(assistant_msg, current_user.id)
    
    emit('response_end', {
        'message': asdict(assistant_msg)
    }, room=session_id)

# ========== MAIN ==========

if __name__ == '__main__':
    # Cria diretórios necessários
    os.makedirs('templates', exist_ok=True)
    
    print("🚀 AI Search Bot Web App")
    print("📁 Banco de dados: chat_sessions.db")
    print("📁 Arquivo de usuários: users.yaml")
    print("🌐 Acesse: http://localhost:5000")
    print("=" * 50)
    
    # Verifica API key
    if not os.getenv('DEEPSEEK_API_KEY'):
        print("⚠️  AVISO: DEEPSEEK_API_KEY não encontrada no .env")
        print("Adicione sua chave ao arquivo .env")
    
    # Informa sobre o usuário padrão
    print("\n📌 Credenciais padrão:")
    print("   Usuário: admin")
    print("   Senha: admin123")
    print("   ⚠️  ALTERE A SENHA APÓS O PRIMEIRO LOGIN!")
    print("=" * 50)
    
    # Inicia servidor
    socketio.run(app, debug=True, host='0.0.0.0', port=5005)