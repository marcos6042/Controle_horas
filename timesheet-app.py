import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import sqlite3
import hashlib
import time
import re

# Inicialização do banco de dados
def init_db():
    conn = sqlite3.connect('timesheet.db')
    c = conn.cursor()
    
    # Tabela de usuários
    c.execute('''CREATE TABLE IF NOT EXISTS usuarios
                 (id INTEGER PRIMARY KEY, 
                  username TEXT UNIQUE, 
                  password TEXT,
                  data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Tabela de contratantes
    c.execute('''CREATE TABLE IF NOT EXISTS contratantes
                 (id INTEGER PRIMARY KEY,
                  nome TEXT,
                  endereco TEXT,
                  telefone TEXT,
                  contato TEXT,
                  tipo_contratante TEXT,
                  ativo BOOLEAN DEFAULT 1,
                  data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Tabela de obras
    c.execute('''CREATE TABLE IF NOT EXISTS obras
                 (id INTEGER PRIMARY KEY,
                  contratante_id INTEGER,
                  local TEXT,
                  prazo TEXT,
                  status TEXT DEFAULT 'Em Andamento',
                  ativo BOOLEAN DEFAULT 1,
                  data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (contratante_id) REFERENCES contratantes(id))''')
    
    # Tabela de colaboradores
    c.execute('''CREATE TABLE IF NOT EXISTS colaboradores
                 (id INTEGER PRIMARY KEY,
                  nome TEXT,
                  endereco TEXT,
                  tipo_documento TEXT,
                  documento TEXT,
                  telefone TEXT,
                  ativo BOOLEAN DEFAULT 1,
                  data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
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
                  total_horas REAL,
                  observacoes TEXT,
                  ativo BOOLEAN DEFAULT 1,
                  data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (colaborador_id) REFERENCES colaboradores(id),
                  FOREIGN KEY (obra_id) REFERENCES obras(id))''')
    
    # Inserir usuário admin padrão se não existir
    admin_password = hashlib.sha256("adm".encode()).hexdigest()
    c.execute("INSERT OR IGNORE INTO usuarios (username, password) VALUES (?, ?)", ("adm", admin_password))
    
    conn.commit()
    conn.close()

# Função para calcular horas trabalhadas
def calcular_horas_trabalhadas(entrada, saida_almoco, entrada_almoco, saida):
    formato = '%H:%M'
    try:
        entrada = datetime.strptime(entrada, formato)
        saida_almoco = datetime.strptime(saida_almoco, formato)
        entrada_almoco = datetime.strptime(entrada_almoco, formato)
        saida = datetime.strptime(saida, formato)
    except ValueError:
        raise ValueError("Formato de horário inválido! Use HH:MM.")
    
    tempo_manha = saida_almoco - entrada
    tempo_tarde = saida - entrada_almoco
    total_segundos = (tempo_manha + tempo_tarde).total_seconds()
    total_horas = total_segundos / 3600
    return round(total_horas, 2)

# Login e cadastro de usuários
def login(username, password):
    conn = sqlite3.connect('timesheet.db')
    c = conn.cursor()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = 0
    
    if st.session_state.login_attempts >= 3:
        st.error("Número máximo de tentativas excedido. Tente novamente em 5 minutos.")
        return False
    
    c.execute("SELECT * FROM usuarios WHERE username=? AND password=?", (username, hashed_password))
    result = c.fetchone()
    conn.close()
    
    if result is None:
        st.session_state.login_attempts += 1
        return False
    
    st.session_state.login_attempts = 0
    return True

def cadastrar_usuario():
    st.title("Cadastro de Novo Usuário")
    
    with st.form("cadastro_usuario"):
        new_username = st.text_input("Usuário")
        new_password = st.text_input("Senha", type="password")
        confirm_password = st.text_input("Confirmar Senha", type="password")
        
        submitted = st.form_submit_button("Cadastrar")
        
        if submitted:
            if len(new_username) < 4:
                st.error("O usuário deve ter pelo menos 4 caracteres!")
                return
            
            if len(new_password) < 6:
                st.error("A senha deve ter pelo menos 6 caracteres!")
                return
            
            if new_password != confirm_password:
                st.error("As senhas não coincidem!")
                return
            
            conn = sqlite3.connect('timesheet.db')
            c = conn.cursor()
            hashed_password = hashlib.sha256(new_password.encode()).hexdigest()
            
            try:
                c.execute("INSERT INTO usuarios (username, password) VALUES (?, ?)", (new_username, hashed_password))
                conn.commit()
                st.success("Usuário cadastrado com sucesso!")
            except sqlite3.IntegrityError:
                st.error("Usuário já existe!")
            finally:
                conn.close()

# Cadastro e gerenciamento de contratantes, obras, colaboradores e tarefas
# (Funções semelhantes para cada entidade, com validações e exclusões lógicas)

# Consultas avançadas
def consultas():
    st.subheader("Consultas")
    
    conn = sqlite3.connect('timesheet.db')
    
    col1, col2, col3 = st.columns(3)
    with col1:
        tipo_consulta = st.selectbox("Tipo de Consulta", ["Contratante", "Colaborador", "Obra"])
    with col2:
        data_inicio = st.date_input("Data Início")
    with col3:
        data_fim = st.date_input("Data Fim")
    
    query_base = """
    SELECT 
        c.nome as Contratante,
        o.local as Obra,
        col.nome as Colaborador,
        t.data as Data,
        t.entrada as Entrada,
        t.saida_almoco as "Saída Almoço",
        t.entrada_almoco as "Retorno Almoço",
        t.saida as Saída,
        t.total_horas as "Total Horas",
        t.observacoes as Observações
    FROM tarefas t
    JOIN obras o ON t.obra_id = o.id
    JOIN contratantes c ON o.contratante_id = c.id
    JOIN colaboradores col ON t.colaborador_id = col.id
    WHERE t.ativo = 1
        AND t.data BETWEEN ? AND ?
    """
    
    params = [data_inicio.strftime('%Y-%m-%d'), data_fim.strftime('%Y-%m-%d')]
    
    df = pd.read_sql_query(query_base, conn, params=params)
    
    if not df.empty:
        st.subheader("Resumo")
        st.metric("Total de Horas", f"{df['Total Horas'].sum():.2f}h")
        st.metric("Média de Horas/Dia", f"{df['Total Horas'].mean():.2f}h")
        st.metric("Dias Trabalhados", len(df['Data'].unique()))
        
        st.subheader("Dados Detalhados")
        st.dataframe(df)
        
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            "Download dos Dados (CSV)",
            csv,
            "dados_consulta.csv",
            "text/csv",
            key='download-csv'
        )
    else:
        st.info("Nenhum resultado encontrado para os filtros selecionados.")
    
    conn.close()

# Dashboard
def dashboard():
    st.subheader("Dashboard")
    
    conn = sqlite3.connect('timesheet.db')
    
    col1, col2, col3 = st.columns(3)
    with col1:
        data_inicio = st.date_input("Data Início", value=datetime.now() - timedelta(days=30))
    with col2:
        data_fim = st.date_input("Data Fim")
    with col3:
        periodo_analise = st.selectbox("Período de Análise", ["Diário", "Semanal", "Mensal"])
    
    query_metricas = """
    SELECT 
        COUNT(DISTINCT t.colaborador_id) as total_colaboradores,
        COUNT(DISTINCT t.obra_id) as total_obras,
        SUM(t.total_horas) as total_horas,
        AVG(t.total_horas) as media_horas_dia
    FROM tarefas t
    WHERE t.ativo = 1
        AND t.data BETWEEN ? AND ?
    """
    
    metricas = pd.read_sql_query(query_metricas, conn, params=(data_inicio.strftime('%Y-%m-%d'), data_fim.strftime('%Y-%m-%d'))).iloc[0]
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total de Colaboradores", int(metricas['total_colaboradores']))
    with col2:
        st.metric("Total de Obras", int(metricas['total_obras']))
    with col3:
        st.metric("Total de Horas", f"{metricas['total_horas']:.2f}h")
    with col4:
        st.metric("Média de Horas/Dia", f"{metricas['media_horas_dia']:.2f}h")
    
    conn.close()

# Relatórios
def gerar_relatorios():
    st.title("Relatórios")
    
    tipo_relatorio = st.selectbox("Selecione o tipo de relatório", [
        "Horas por Colaborador",
        "Horas por Obra",
        "Horas por Contratante",
        "Produtividade",
        "Resumo Mensal"
    ])
    
    col1, col2 = st.columns(2)
    with col1:
        data_inicio = st.date_input("Data Início")
    with col2:
        data_fim = st.date_input("Data Fim")
    
    conn = sqlite3.connect('timesheet.db')
    
    if tipo_relatorio == "Horas por Colaborador":
        query = """
        SELECT 
            col.nome as Colaborador,
            COUNT(DISTINCT t.data) as Dias_Trabalhados,
            SUM(t.total_horas) as Total_Horas,
            AVG(t.total_horas) as Media_Horas_Dia,
            GROUP_CONCAT(DISTINCT o.local) as Obras
        FROM tarefas t
        JOIN colaboradores col ON t.colaborador_id = col.id
        JOIN obras o ON t.obra_id = o.id
        WHERE t.ativo = 1
            AND t.data BETWEEN ? AND ?
        GROUP BY col.nome
        ORDER BY Total_Horas DESC
        """
    
    # (Outros tipos de relatórios seguem a mesma estrutura)
    
    df = pd.read_sql_query(query, conn, params=(data_inicio.strftime('%Y-%m-%d'), data_fim.strftime('%Y-%m-%d')))
    
    if not df.empty:
        st.subheader(f"Relatório: {tipo_relatorio}")
        st.dataframe(df)
        
        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button(
            f"Download do Relatório - {tipo_relatorio} (CSV)",
            csv,
            f"relatorio_{tipo_relatorio.lower().replace(' ', '_')}.csv",
            "text/csv",
            key='download-relatorio'
        )
    else:
        st.info("Nenhum dado encontrado para o período selecionado.")
    
    conn.close()

# Configurações
def configuracoes():
    st.title("Configurações")
    
    if st.session_state.username == "adm":
        st.subheader("Configurações do Sistema")
        
        if st.button("Fazer Backup do Banco de Dados"):
            try:
                data_atual = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = f"backup_timesheet_{data_atual}.db"
                
                conn = sqlite3.connect('timesheet.db')
                backup = sqlite3.connect(backup_file)
                conn.backup(backup)
                backup.close()
                conn.close()
                
                with open(backup_file, 'rb') as f:
                    bytes_data = f.read()
                
                st.download_button(
                    "Download do Backup",
                    bytes_data,
                    backup_file,
                    "application/x-sqlite3",
                    key='download-backup'
                )
                
                st.success("Backup realizado com sucesso!")
            except Exception as e:
                st.error(f"Erro ao realizar backup: {str(e)}")
        
        uploaded_file = st.file_uploader("Restaurar Backup", type=['db'])
        if uploaded_file is not None:
            if st.button("Restaurar Banco de Dados"):
                try:
                    data_atual = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_atual = f"backup_antes_restauracao_{data_atual}.db"
                    
                    conn_atual = sqlite3.connect('timesheet.db')
                    backup = sqlite3.connect(backup_atual)
                    conn_atual.backup(backup)
                    backup.close()
                    conn_atual.close()
                    
                    with open('timesheet.db', 'wb') as f:
                        f.write(uploaded_file.getbuffer())
                    
                    st.success("Banco de dados restaurado com sucesso!")
                    st.warning("O sistema será reiniciado.")
                    time.sleep(3)
                    st.experimental_rerun()
                except Exception as e:
                    st.error(f"Erro ao restaurar banco de dados: {str(e)}")
    
    st.subheader("Configurações do Usuário")
    
    with st.form("alterar_senha"):
        senha_atual = st.text_input("Senha Atual", type="password")
        nova_senha = st.text_input("Nova Senha", type="password")
        confirmar_senha = st.text_input("Confirmar Nova Senha", type="password")
        
        if st.form_submit_button("Alterar Senha"):
            if nova_senha != confirmar_senha:
                st.error("As senhas não coincidem!")
                return
            
            if len(nova_senha) < 6:
                st.error("A nova senha deve ter pelo menos 6 caracteres!")
                return
            
            conn = sqlite3.connect('timesheet.db')
            c = conn.cursor()
            
            senha_hash = hashlib.sha256(senha_atual.encode()).hexdigest()
            c.execute("SELECT id FROM usuarios WHERE username = ? AND password = ?", (st.session_state.username, senha_hash))
            
            if c.fetchone() is None:
                st.error("Senha atual incorreta!")
            else:
                nova_senha_hash = hashlib.sha256(nova_senha.encode()).hexdigest()
                c.execute("UPDATE usuarios SET password = ? WHERE username = ?", (nova_senha_hash, st.session_state.username))
                conn.commit()
                st.success("Senha alterada com sucesso!")
            
            conn.close()

# Função principal
def main():
    st.set_page_config(page_title="Controle de Horas", page_icon="⏰", layout="wide")
    
    init_db()
    
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False
    
    if not st.session_state.logged_in:
        st.title("Sistema de Controle de Horas")
        
        tab1, tab2 = st.tabs(["Login", "Novo Usuário"])
        
        with tab1:
            with st.form("login_form"):
                username = st.text_input("Usuário")
                password = st.text_input("Senha", type="password")
                submitted = st.form_submit_button("Login")
                
                if submitted:
                    if login(username, password):
                        st.session_state.logged_in = True
                        st.session_state.username = username
                        st.experimental_rerun()
                    else:
                        st.error("Usuário ou senha incorretos!")
        
        with tab2:
            cadastrar_usuario()
    
    else:
        with st.sidebar:
            st.title(f"Bem-vindo(a), {st.session_state.username}!")
            
            menu_options = {
                "📊 Dashboard": "Dashboard",
                "📝 Cadastros": "Cadastros",
                "🔍 Consultas": "Consultas",
                "📋 Relatórios": "Relatórios",
                "⚙️ Configurações": "Configurações",
                "🚪 Sair": "Sair"
            }
            
            menu_choice = st.sidebar.selectbox("Menu", list(menu_options.keys()), format_func=lambda x: x.split(" ")[1])
            selected = menu_options[menu_choice]
        
        if selected == "Dashboard":
            dashboard()
        elif selected == "Cadastros":
            st.title("Cadastros")
            # (Lógica para cadastros)
        elif selected == "Consultas":
            consultas()
        elif selected == "Relatórios":
            gerar_relatorios()
        elif selected == "Configurações":
            configuracoes()
        else:
            st.session_state.logged_in = False
            st.session_state.username = None
            st.experimental_rerun()

if __name__ == "__main__":
    main()
