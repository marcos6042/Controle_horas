import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime
import sqlite3
import hashlib

# Configuração inicial do banco de dados
def init_db():
    conn = sqlite3.connect('timesheet.db')
    c = conn.cursor()
    
    # Tabela de usuários
    c.execute('''CREATE TABLE IF NOT EXISTS usuarios
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    
    # Tabela de contratantes
    c.execute('''CREATE TABLE IF NOT EXISTS contratantes
                 (id INTEGER PRIMARY KEY,
                  nome TEXT,
                  endereco TEXT,
                  telefone TEXT,
                  contato TEXT,
                  tipo_contratante TEXT)''')
    
    # Tabela de obras
    c.execute('''CREATE TABLE IF NOT EXISTS obras
                 (id INTEGER PRIMARY KEY,
                  contratante_id INTEGER,
                  local TEXT,
                  prazo TEXT,
                  FOREIGN KEY (contratante_id) REFERENCES contratantes(id))''')
    
    # Tabela de colaboradores
    c.execute('''CREATE TABLE IF NOT EXISTS colaboradores
                 (id INTEGER PRIMARY KEY,
                  nome TEXT,
                  endereco TEXT,
                  tipo_documento TEXT,
                  documento TEXT,
                  telefone TEXT)''')
    
    # Tabela de tarefas
    c.execute('''CREATE TABLE IF NOT EXISTS tarefas
                 (id INTEGER PRIMARY KEY,
                  colaborador_id INTEGER,
                  obra_id INTEGER,
                  data TEXT,
                  entrada TEXT,
                  saida_almoco TEXT,
                  entrada_almoco TEXT,
                  saida TEXT,
                  FOREIGN KEY (colaborador_id) REFERENCES colaboradores(id),
                  FOREIGN KEY (obra_id) REFERENCES obras(id))''')
    
    # Inserir usuário admin padrão se não existir
    admin_password = hashlib.sha256("adm".encode()).hexdigest()
    c.execute("INSERT OR IGNORE INTO usuarios (username, password) VALUES (?, ?)",
             ("adm", admin_password))
    
    conn.commit()
    conn.close()

# Função de login
def login(username, password):
    conn = sqlite3.connect('timesheet.db')
    c = conn.cursor()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    c.execute("SELECT * FROM usuarios WHERE username=? AND password=?",
             (username, hashed_password))
    result = c.fetchone()
    conn.close()
    return result is not None

# Função para cadastrar novo usuário
def cadastrar_usuario():
    st.title("Cadastro de Novo Usuário")
    new_username = st.text_input("Usuário")
    new_password = st.text_input("Senha", type="password")
    confirm_password = st.text_input("Confirmar Senha", type="password")
    
    if st.button("Cadastrar"):
        if new_password == confirm_password:
            conn = sqlite3.connect('timesheet.db')
            c = conn.cursor()
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            try:
                c.execute("INSERT INTO usuarios (username, password) VALUES (?, ?)",
                         (new_username, hashed_password))
                conn.commit()
                st.success("Usuário cadastrado com sucesso!")
                st.button("Voltar ao Login")
            except sqlite3.IntegrityError:
                st.error("Usuário já existe!")
            conn.close()
        else:
            st.error("As senhas não coincidem!")

# Função para cadastrar contratante
def cadastrar_contratante():
    st.subheader("Cadastro de Contratante")
    nome = st.text_input("Nome")
    endereco = st.text_input("Endereço")
    telefone = st.text_input("Telefone")
    contato = st.text_input("Contato")
    tipo = st.selectbox("Tipo", ["Contratante Direto", "Subcontratante"])
    
    if st.button("Salvar Contratante"):
        conn = sqlite3.connect('timesheet.db')
        c = conn.cursor()
        c.execute("""INSERT INTO contratantes 
                    (nome, endereco, telefone, contato, tipo_contratante)
                    VALUES (?, ?, ?, ?, ?)""",
                 (nome, endereco, telefone, contato, tipo))
        conn.commit()
        conn.close()
        st.success("Contratante cadastrado com sucesso!")

# Função para cadastrar obra
def cadastrar_obra():
    st.subheader("Cadastro de Obra")
    
    # Buscar contratantes para o dropdown
    conn = sqlite3.connect('timesheet.db')
    c = conn.cursor()
    c.execute("SELECT id, nome FROM contratantes")
    contratantes = c.fetchall()
    conn.close()
    
    contratante = st.selectbox("Contratante", 
                              options=[c[1] for c in contratantes],
                              format_func=lambda x: x)
    local = st.text_input("Local da Obra")
    prazo = st.date_input("Prazo")
    
    if st.button("Salvar Obra"):
        conn = sqlite3.connect('timesheet.db')
        c = conn.cursor()
        contratante_id = [c[0] for c in contratantes if c[1] == contratante][0]
        c.execute("""INSERT INTO obras (contratante_id, local, prazo)
                    VALUES (?, ?, ?)""",
                 (contratante_id, local, prazo.strftime('%Y-%m-%d')))
        conn.commit()
        conn.close()
        st.success("Obra cadastrada com sucesso!")

# Função para cadastrar colaborador
def cadastrar_colaborador():
    st.subheader("Cadastro de Colaborador")
    nome = st.text_input("Nome")
    endereco = st.text_input("Endereço")
    tipo_doc = st.selectbox("Tipo de Documento", 
                           ["Documento Identificação", "Passaporte", "Outros"])
    documento = st.text_input("Número do Documento")
    telefone = st.text_input("Telefone")
    
    if st.button("Salvar Colaborador"):
        conn = sqlite3.connect('timesheet.db')
        c = conn.cursor()
        c.execute("""INSERT INTO colaboradores 
                    (nome, endereco, tipo_documento, documento, telefone)
                    VALUES (?, ?, ?, ?, ?)""",
                 (nome, endereco, tipo_doc, documento, telefone))
        conn.commit()
        conn.close()
        st.success("Colaborador cadastrado com sucesso!")

# Função para registrar tarefa
def registrar_tarefa():
    st.subheader("Registro de Tarefa")
    
    conn = sqlite3.connect('timesheet.db')
    c = conn.cursor()
    
    # Buscar colaboradores
    c.execute("SELECT id, nome FROM colaboradores")
    colaboradores = c.fetchall()
    
    # Buscar obras
    c.execute("SELECT id, local FROM obras")
    obras = c.fetchall()
    
    colaborador = st.selectbox("Colaborador", 
                              options=[c[1] for c in colaboradores],
                              format_func=lambda x: x)
    obra = st.selectbox("Obra", 
                       options=[o[1] for o in obras],
                       format_func=lambda x: x)
    data = st.date_input("Data")
    entrada = st.time_input("Entrada")
    saida_almoco = st.time_input("Saída Almoço")
    entrada_almoco = st.time_input("Retorno Almoço")
    saida = st.time_input("Saída")
    
    if st.button("Registrar"):
        colaborador_id = [c[0] for c in colaboradores if c[1] == colaborador][0]
        obra_id = [o[0] for o in obras if o[1] == obra][0]
        
        c.execute("""INSERT INTO tarefas 
                    (colaborador_id, obra_id, data, entrada, saida_almoco,
                     entrada_almoco, saida)
                    VALUES (?, ?, ?, ?, ?, ?, ?)""",
                 (colaborador_id, obra_id, data.strftime('%Y-%m-%d'),
                  entrada.strftime('%H:%M'),
                  saida_almoco.strftime('%H:%M'),
                  entrada_almoco.strftime('%H:%M'),
                  saida.strftime('%H:%M')))
        conn.commit()
        st.success("Tarefa registrada com sucesso!")
    
    conn.close()

# Função para consultas
def consultas():
    st.subheader("Consultas")
    tipo_consulta = st.selectbox("Tipo de Consulta",
                                ["Contratante", "Colaborador", "Obra"])
    
    data_inicio = st.date_input("Data Início")
    data_fim = st.date_input("Data Fim")
    
    conn = sqlite3.connect('timesheet.db')
    
    if tipo_consulta == "Contratante":
        query = """
        SELECT c.nome as Contratante, o.local as Obra, col.nome as Colaborador,
               t.data as Data, t.entrada, t.saida_almoco,
               t.entrada_almoco, t.saida
        FROM tarefas t
        JOIN obras o ON t.obra_id = o.id
        JOIN contratantes c ON o.contratante_id = c.id
        JOIN colaboradores col ON t.colaborador_id = col.id
        WHERE t.data BETWEEN ? AND ?
        """
    elif tipo_consulta == "Colaborador":
        query = """
        SELECT col.nome as Colaborador, o.local as Obra,
               c.nome as Contratante, t.data as Data,
               t.entrada, t.saida_almoco, t.entrada_almoco, t.saida
        FROM tarefas t
        JOIN colaboradores col ON t.colaborador_id = col.id
        JOIN obras o ON t.obra_id = o.id
        JOIN contratantes c ON o.contratante_id = c.id
        WHERE t.data BETWEEN ? AND ?
        """
    else:  # Obra
        query = """
        SELECT o.local as Obra, c.nome as Contratante,
               col.nome as Colaborador, t.data as Data,
               t.entrada, t.saida_almoco, t.entrada_almoco, t.saida
        FROM tarefas t
        JOIN obras o ON t.obra_id = o.id
        JOIN contratantes c ON o.contratante_id = c.id
        JOIN colaboradores col ON t.colaborador_id = col.id
        WHERE t.data BETWEEN ? AND ?
        """
    
    df = pd.read_sql_query(query, conn,
                          params=(data_inicio.strftime('%Y-%m-%d'),
                                 data_fim.strftime('%Y-%m-%d')))
    conn.close()
    
    if not df.empty:
        st.dataframe(df)
    else:
        st.info("Nenhum resultado encontrado para os filtros selecionados.")

# Função para dashboard
def dashboard():
    st.subheader("Dashboard")
    
    conn = sqlite3.connect('timesheet.db')
    
    # Total de horas trabalhadas
    query_horas = """
    SELECT 
        SUM(
            (julianday(saida) - julianday(entrada)) * 24 -
            (julianday(entrada_almoco) - julianday(saida_almoco)) * 24
        ) as total_horas
    FROM tarefas
    """
    total_horas = pd.read_sql_query(query_horas, conn).iloc[0, 0]
    
    # Total de obras
    query_obras = "SELECT COUNT(*) as total_obras FROM obras"
    total_obras = pd.read_sql_query(query_obras, conn).iloc[0, 0]
    
    # Métricas principais
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Total de Horas Trabalhadas", f"{total_horas:.2f}h")
    with col2:
        st.metric("Total de Obras", total_obras)
    
    # Gráfico de pizza - Distribuição de horas por contratante
    query_contratantes = """
    SELECT 
        c.nome as contratante,
        SUM(
            (julianday(t.saida) - julianday(t.entrada)) * 24 -
            (julianday(t.entrada_almoco) - julianday(t.saida_almoco)) * 24
        ) as horas
    FROM tarefas t
    JOIN obras o ON t.obra_id = o.id
    JOIN contratantes c ON o.contratante_id = c.id
    GROUP BY c.nome
    """
    df_contratantes = pd.read_sql_query(query_contratantes, conn)
    
    fig_pizza = px.pie(df_contratantes, values='horas', names='contratante',
                      title='Distribuição de Horas por Contratante')
    st.plotly_chart(fig_pizza)
    
    # Gráfico de colunas - Horas por obra
    query_obras = """
    SELECT 
        o.local as obra,
        SUM(
            (julianday(t.saida) - julianday(t.entrada)) * 24 -
            (julianday(t.entrada_almoco) - julianday(t.saida_almoco)) * 24
        ) as horas
    FROM tarefas t
    JOIN obras o ON t.obra_id = o.id
    GROUP BY o.local
    """
    df_obras = pd.read_sql_query(query_obras, conn)
    
    fig_colunas = px.bar(df_obras, x='obra', y='horas',
                        title='Total de Horas por Obra')
    st.plotly_chart(fig_colunas)
    
    conn.close()

# Interface principal
def main():
    st.set_page_config(page_title="Controle de Horas", layout="wide")
    
    # Inicializar banco de dados
    init_db()
    
    # Verificar se usuário está logado
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    if not st.session_state.logged_in:
        st.title("Login")
        col1, col2 = st.columns(2)
        
        with col1:
            username = st.text_input("Usuário")
            password = st.text_input("Senha", type="password")
            if st.button("Login"):
                if login(username, password):
                    st.session_state.logged_in = True
                    st.experimental_rerun()
                else:
                    st.error("