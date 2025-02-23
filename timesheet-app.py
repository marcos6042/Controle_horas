import streamlit as st
import pandas as pd
import plotly.express as px
from datetime import datetime, timedelta
import sqlite3
import hashlib
import time
import re

# Configuração inicial do banco de dados
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
    c.execute("INSERT OR IGNORE INTO usuarios (username, password) VALUES (?, ?)",
             ("adm", admin_password))
    
    conn.commit()
    conn.close()

def calcular_horas_trabalhadas(entrada, saida_almoco, entrada_almoco, saida):
    """Calcula o total de horas trabalhadas considerando o intervalo de almoço"""
    formato = '%H:%M'
    
    # Converte strings para objetos datetime
    entrada = datetime.strptime(entrada, formato)
    saida_almoco = datetime.strptime(saida_almoco, formato)
    entrada_almoco = datetime.strptime(entrada_almoco, formato)
    saida = datetime.strptime(saida, formato)
    
    # Calcula as diferenças
    tempo_manha = saida_almoco - entrada
    tempo_tarde = saida - entrada_almoco
    
    # Soma os períodos e converte para horas
    total_segundos = (tempo_manha + tempo_tarde).total_seconds()
    total_horas = total_segundos / 3600
    
    return round(total_horas, 2)

# Função de login com controle de tentativas
def login(username, password):
    conn = sqlite3.connect('timesheet.db')
    c = conn.cursor()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    
    if 'login_attempts' not in st.session_state:
        st.session_state.login_attempts = 0
        
    if st.session_state.login_attempts >= 3:
        st.error("Número máximo de tentativas excedido. Tente novamente em 5 minutos.")
        return False
    
    c.execute("SELECT * FROM usuarios WHERE username=? AND password=?",
             (username, hashed_password))
    result = c.fetchone()
    conn.close()
    
    if result is None:
        st.session_state.login_attempts += 1
        return False
    
    st.session_state.login_attempts = 0
    return True

# Função para cadastrar novo usuário com validações
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
                c.execute("INSERT INTO usuarios (username, password) VALUES (?, ?)",
                         (new_username, hashed_password))
                conn.commit()
                st.success("Usuário cadastrado com sucesso!")
                if st.button("Voltar ao Login"):
                    st.session_state.page = "login"
            except sqlite3.IntegrityError:
                st.error("Usuário já existe!")
            finally:
                conn.close()

# Função para cadastrar contratante com validações
def cadastrar_contratante():
    st.subheader("Cadastro de Contratante")
    
    with st.form("cadastro_contratante"):
        nome = st.text_input("Nome")
        endereco = st.text_input("Endereço")
        telefone = st.text_input("Telefone")
        contato = st.text_input("Contato")
        tipo = st.selectbox("Tipo", ["Contratante Direto", "Subcontratante"])
        
        submitted = st.form_submit_button("Salvar Contratante")
        
        if submitted:
            if not nome or not endereco or not telefone or not contato:
                st.error("Todos os campos são obrigatórios!")
                return
                
            conn = sqlite3.connect('timesheet.db')
            c = conn.cursor()
            
            try:
                c.execute("""INSERT INTO contratantes 
                            (nome, endereco, telefone, contato, tipo_contratante)
                            VALUES (?, ?, ?, ?, ?)""",
                         (nome, endereco, telefone, contato, tipo))
                conn.commit()
                st.success("Contratante cadastrado com sucesso!")
            except Exception as e:
                st.error(f"Erro ao cadastrar contratante: {str(e)}")
            finally:
                conn.close()

# Função para editar/excluir contratante
def gerenciar_contratante():
    st.subheader("Gerenciar Contratantes")
    
    conn = sqlite3.connect('timesheet.db')
    df = pd.read_sql_query("SELECT * FROM contratantes WHERE ativo = 1", conn)
    
    if not df.empty:
        contratante_selecionado = st.selectbox(
            "Selecione um contratante para editar/excluir",
            df['nome'].tolist()
        )
        
        contratante = df[df['nome'] == contratante_selecionado].iloc[0]
        
        with st.form("editar_contratante"):
            nome = st.text_input("Nome", value=contratante['nome'])
            endereco = st.text_input("Endereço", value=contratante['endereco'])
            telefone = st.text_input("Telefone", value=contratante['telefone'])
            contato = st.text_input("Contato", value=contratante['contato'])
            tipo = st.selectbox("Tipo", 
                              ["Contratante Direto", "Subcontratante"],
                              index=0 if contratante['tipo_contratante'] == "Contratante Direto" else 1)
            
            col1, col2 = st.columns(2)
            
            with col1:
                if st.form_submit_button("Atualizar"):
                    c = conn.cursor()
                    c.execute("""UPDATE contratantes 
                                SET nome=?, endereco=?, telefone=?, 
                                    contato=?, tipo_contratante=?
                                WHERE id=?""",
                             (nome, endereco, telefone, contato, 
                              tipo, contratante['id']))
                    conn.commit()
                    st.success("Contratante atualizado com sucesso!")
                    
            with col2:
                if st.form_submit_button("Excluir"):
                    if st.warning("Tem certeza que deseja excluir este contratante?"):
                        c = conn.cursor()
                        c.execute("UPDATE contratantes SET ativo = 0 WHERE id=?",
                                (contratante['id'],))
                        conn.commit()
                        st.success("Contratante excluído com sucesso!")
    
    conn.close()

# Função para cadastrar obra com validações
def cadastrar_obra():
    st.subheader("Cadastro de Obra")
    
    conn = sqlite3.connect('timesheet.db')
    contratantes = pd.read_sql_query(
        "SELECT id, nome FROM contratantes WHERE ativo = 1", 
        conn
    )
    
    if contratantes.empty:
        st.warning("Cadastre um contratante primeiro!")
        return
    
    with st.form("cadastro_obra"):
        contratante = st.selectbox(
            "Contratante",
            options=contratantes['nome'].tolist(),
            format_func=lambda x: x
        )
        local = st.text_input("Local da Obra")
        prazo = st.date_input("Prazo")
        status = st.selectbox(
            "Status",
            ["Em Andamento", "Concluída", "Paralisada"]
        )
        
        submitted = st.form_submit_button("Salvar Obra")
        
        if submitted:
            if not local:
                st.error("O local da obra é obrigatório!")
                return
                
            contratante_id = contratantes[
                contratantes['nome'] == contratante
            ]['id'].iloc[0]
            
            c = conn.cursor()
            try:
                c.execute("""INSERT INTO obras 
                            (contratante_id, local, prazo, status)
                            VALUES (?, ?, ?, ?)""",
                         (contratante_id, local, 
                          prazo.strftime('%Y-%m-%d'), status))
                conn.commit()
                st.success("Obra cadastrada com sucesso!")
            except Exception as e:
                st.error(f"Erro ao cadastrar obra: {str(e)}")
            finally:
                conn.close()

# Função para registrar tarefa com validações
def registrar_tarefa():
    st.subheader("Registro de Tarefa")
    
    conn = sqlite3.connect('timesheet.db')
    
    # Buscar colaboradores ativos
    colaboradores = pd.read_sql_query(
        "SELECT id, nome FROM colaboradores WHERE ativo = 1",
        conn
    )
    
    # Buscar obras ativas
    obras = pd.read_sql_query(
        "SELECT id, local FROM obras WHERE ativo = 1 AND status = 'Em Andamento'",
        conn
    )
    
    if colaboradores.empty or obras.empty:
        st.warning("É necessário ter colaboradores e obras cadastrados!")
        return
    
    with st.form("registro_tarefa"):
        col1, col2 = st.columns(2)
        
        with col1:
            colaborador = st.selectbox(
                "Colaborador",
                options=colaboradores['nome'].tolist()
            )
            data = st.date_input("Data")
            entrada = st.time_input("Entrada")
            saida_almoco = st.time_input("Saída Almoço")
            
        with col2:
            obra = st.selectbox(
                "Obra",
                options=obras['local'].tolist()
            )
            entrada_almoco = st.time_input("Retorno Almoço")
            saida = st.time_input("Saída")
        
        observacoes = st.text_area("Observações")
        submitted = st.form_submit_button("Registrar")
        
        if submitted:
            # Validações
            if (entrada >= saida_almoco or
                saida_almoco >= entrada_almoco or
                entrada_almoco >= saida):
                st.error("Horários inválidos!")
                return
            
            colaborador_id = colaboradores[
                colaboradores['nome'] == colaborador
            ]['id'].iloc[0]
            obra_id = obras[
                obras['local'] == obra
            ]['id'].iloc[0]
            
            # Calcular total de horas
            total_horas = calcular_horas_trabalhadas(
                entrada.strftime('%H:%M'),
                saida_almoco.strftime('%H:%M'),
                entrada_almoco.strftime('%H:%M'),
                saida.strftime('%H:%M')
            )
            
            try:
                c = conn.cursor()
                c.execute("""INSERT INTO tarefas 
                            (colaborador_id, obra_id, data, entrada,
                             saida_almoco, entrada_almoco, saida,
                             total_horas, observacoes)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                         (colaborador_id, obra_id,
                          data.strftime('%Y-%m-%d'),
                          entrada.strftime('%H:%M'),
                          saida_almoco.strftime('%H:%M'),
                          entrada_almoco.strftime('%H:%M'),
                          saida.strftime('%H:%M'),
                          total_horas, observacoes))
                conn.commit()
                st.success(f"Tarefa registrada com sucesso! Total de horas: {total_horas}h")
            except Exception as e:
                st.error(f"Erro ao registrar tarefa: {str(e)}")
            finally:
                conn.close()

# Função para consultas avançadas
def consultas():
    st.subheader("Consultas")
    
    conn = sqlite3.connect('timesheet.db')
    
    # Filtros
    col1, col2, col3 = st.columns(3)
    
    with col1:
        tipo_consulta = st.selectbox(
            "Tipo de Consulta",
            ["Contratante", "Colaborador", "Obra"]
        )
    
    with col2:
        data_inicio = st.date_input("Data Início")
    
    with col3:
        data_fim = st.date_input("Data Fim")
    
    # Filtros adicionais baseados no tipo de consulta
    if tipo_consulta == "Contratante":
        contratantes = pd.read_sql_query(
            "SELECT DISTINCT nome FROM contratantes WHERE ativo = 1",
            conn
        )
        contratante_filtro = st.multiselect(
            "Filtrar por Contratantes",
            options=contratantes['nome'].tolist()
        )
    
    elif tipo_consulta == "Colaborador":
        colaboradores = pd.read_sql_query(
            "SELECT DISTINCT nome FROM colaboradores WHERE ativo = 1",
            conn
        )
        colaborador_filtro = st.multiselect(
            "Filtrar por Colaboradores",
            options=colaboradores['nome'].tolist()
        )
    
    else:  # Obra
        obras = pd.read_sql_query(
            "SELECT DISTINCT local FROM obras WHERE ativo = 1",
            conn
        )
        obra_filtro = st.multiselect(
            "Filtrar por Obras",
            options=obras['local'].tolist()
        )
    
    # Construir query base
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
    
    params = [data_inicio.strftime('%Y-%m-%d'),
              data_fim.strftime('%Y-%m-%d')]
    
    # Adicionar filtros específicos
    if tipo_consulta == "Contratante" and contratante_filtro:
        query_base += " AND c.nome IN ({})".format(
            ','.join(['?'] * len(contratante_filtro))
        )
        params.extend(contratante_filtro)
    
    elif tipo_consulta == "Colaborador" and colaborador_filtro:
        query_base += " AND col.nome IN ({})".format(
            ','.join(['?'] * len(colaborador_filtro))
        )
        params.extend(colaborador_filtro)
    
    elif tipo_consulta == "Obra" and obra_filtro:
        query_base += " AND o.local IN ({})".format(
            ','.join(['?'] * len(obra_filtro))
        )
        params.extend(obra_filtro)
    
    # Ordenação
    query_base += " ORDER BY t.data DESC"
    
    # Executar consulta
    df = pd.read_sql_query(query_base, conn, params=params)
    
    if not df.empty:
        # Mostrar resumo
        st.subheader("Resumo")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric(
                "Total de Horas",
                f"{df['Total Horas'].sum():.2f}h"
            )
        
        with col2:
            st.metric(
                "Média de Horas/Dia",
                f"{df['Total Horas'].mean():.2f}h"
            )
        
        with col3:
            st.metric(
                "Dias Trabalhados",
                len(df['Data'].unique())
            )
        
        # Mostrar dados detalhados
        st.subheader("Dados Detalhados")
        st.dataframe(df)
        
        # Opção para download
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

# Função para dashboard aprimorado
def dashboard():
    st.subheader("Dashboard")
    
    conn = sqlite3.connect('timesheet.db')
    
    # Filtros
    col1, col2, col3 = st.columns(3)
    
    with col1:
        data_inicio = st.date_input("Data Início",
                                   value=datetime.now() - timedelta(days=30))
    
    with col2:
        data_fim = st.date_input("Data Fim")
    
    with col3:
        periodo_analise = st.selectbox(
            "Período de Análise",
            ["Diário", "Semanal", "Mensal"]
        )
    
    # Métricas principais
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
    
    metricas = pd.read_sql_query(
        query_metricas,
        conn,
        params=(data_inicio.strftime('%Y-%m-%d'),
                data_fim.strftime('%Y-%m-%d'))
    ).iloc[0]
    
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total de Colaboradores", int(metricas['total_colaboradores']))
    with col2:
        st.metric("Total de Obras", int(metricas['total_obras']))
    with col3:
        st.metric("Total de Horas", f"{metricas['total_horas']:.2f}h")
    with col4:
        st.metric("Média de Horas/Dia", f"{metricas['media_horas_dia']:.2f}h")
    
    # Gráficos
    col1, col2 = st.columns(2)
    
    with col1:
        # Horas por contratante (pizza)
        query_contratantes = """
        SELECT 
            c.nome as contratante,
            SUM(t.total_horas) as horas
        FROM tarefas t
        JOIN obras o ON t.obra_id = o.id
        JOIN contratantes c ON o.contratante_id = c.id
        WHERE t.ativo = 1
            AND t.data BETWEEN ? AND ?
        GROUP BY c.nome
        """
        
        df_contratantes = pd.read_sql_query(
            query_contratantes,
            conn,
            params=(data_inicio.strftime('%Y-%m-%d'),
                   data_fim.strftime('%Y-%m-%d'))
        )
        
        if not df_contratantes.empty:
            fig_pizza = px.pie(
                df_contratantes,
                values='horas',
                names='contratante',
                title='Distribuição de Horas por Contratante'
            )
            st.plotly_chart(fig_pizza)
    
    with col2:
        # Horas por obra (barras)
        query_obras = """
        SELECT 
            o.local as obra,
            SUM(t.total_horas) as horas
        FROM tarefas t
        JOIN obras o ON t.obra_id = o.id
        WHERE t.ativo = 1
            AND t.data BETWEEN ? AND ?
        GROUP BY o.local
        ORDER BY horas DESC
        LIMIT 10
        """
        
        df_obras = pd.read_sql_query(
            query_obras,
            conn,
            params=(data_inicio.strftime('%Y-%m-%d'),
                   data_fim.strftime('%Y-%m-%d'))
        )
        
        if not df_obras.empty:
            fig_barras = px.bar(
                df_obras,
                x='obra',
                y='horas',
                title='Top 10 Obras por Horas Trabalhadas'
            )
            st.plotly_chart(fig_barras)
    
    # Evolução temporal
    query_evolucao = """
    SELECT 
        date(t.data) as data,
        SUM(t.total_horas) as horas
    FROM tarefas t
    WHERE t.ativo = 1
        AND t.data BETWEEN ? AND ?
    GROUP BY date(t.data)
    ORDER BY data
    """
    
    df_evolucao = pd.read_sql_query(
        query_evolucao,
        conn,
        params=(data_inicio.strftime('%Y-%m-%d'),
                data_fim.strftime('%Y-%m-%d'))
    )
    
    if not df_evolucao.empty:
        fig_linha = px.line(
            df_evolucao,
            x='data',
            y='horas',
            title='Evolução do Total de Horas Trabalhadas'
        )
        st.plotly_chart(fig_linha)
    
    conn.close()

# Função principal atualizada
def main():
    st.set_page_config(
        page_title="Controle de Horas",
        page_icon="⏰",
        layout="wide"
    )
    
    # Inicializar banco de dados
    init_db()
    
    # Verificar se usuário está logado
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
        # Menu lateral
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
            
            menu_choice = st.sidebar.selectbox(
                "Menu",
                list(menu_options.keys()),
                format_func=lambda x: x.split(" ")[1]
            )
            
            selected = menu_options[menu_choice]
        
        # Conteúdo principal
        if selected == "Dashboard":
            dashboard()
        
        elif selected == "Cadastros":
            st.title("Cadastros")
            
            cadastro_options = {
                "Contratantes": {
                    "Novo Contratante": cadastrar_contratante,
                    "Gerenciar Contratantes": gerenciar_contratante
                },
                "Obras": {
                    "Nova Obra": cadastrar_obra,
                    "Gerenciar Obras": gerenciar_obra
                },
                "Colaboradores": {
                    "Novo Colaborador": cadastrar_colaborador,
                    "Gerenciar Colaboradores": gerenciar_colaborador
                },
                "Tarefas": {
                    "Nova Tarefa": registrar_tarefa,
                    "Gerenciar Tarefas": gerenciar_tarefa
                }
            }
            
            tipo_cadastro = st.selectbox(
                "Selecione o tipo de cadastro",
                list(cadastro_options.keys())
            )
            
            acao = st.radio(
                "Ação",
                list(cadastro_options[tipo_cadastro].keys())
            )
            
            cadastro_options[tipo_cadastro][acao]()
        
        elif selected == "Consultas":
            consultas()
        
        elif selected == "Relatórios":
            gerar_relatorios()
        
        elif selected == "Configurações":
            configuracoes()
        
        else:  # Sair
            st.session_state.logged_in = False
            st.session_state.username = None
            st.experimental_rerun()

# Função para gerar relatórios
def gerar_relatorios():
    st.title("Relatórios")
    
    tipo_relatorio = st.selectbox(
        "Selecione o tipo de relatório",
        ["Horas por Colaborador",
         "Horas por Obra",
         "Horas por Contratante",
         "Produtividade",
         "Resumo Mensal"]
    )
    
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
    
    elif tipo_relatorio == "Horas por Obra":
        query = """
        SELECT 
            o.local as Obra,
            c.nome as Contratante,
            COUNT(DISTINCT t.colaborador_id) as Total_Colaboradores,
            SUM(t.total_horas) as Total_Horas,
            AVG(t.total_horas) as Media_Horas_Dia
        FROM tarefas t
        JOIN obras o ON t.obra_id = o.id
        JOIN contratantes c ON o.contratante_id = c.id
        WHERE t.ativo = 1
            AND t.data BETWEEN ? AND ?
        GROUP BY o.local
        ORDER BY Total_Horas DESC
        """
    
    elif tipo_relatorio == "Horas por Contratante":
        query = """
        SELECT 
            c.nome as Contratante,
            COUNT(DISTINCT o.id) as Total_Obras,
            COUNT(DISTINCT t.colaborador_id) as Total_Colaboradores,
            SUM(t.total_horas) as Total_Horas,
            AVG(t.total_horas) as Media_Horas_Dia
        FROM tarefas t
        JOIN obras o ON t.obra_id = o.id
        JOIN contratantes c ON o.contratante_id = c.id
        WHERE t.ativo = 1
            AND t.data BETWEEN ? AND ?
        GROUP BY c.nome
        ORDER BY Total_Horas DESC
        """
    
    elif tipo_relatorio == "Produtividade":
        query = """
        SELECT 
            col.nome as Colaborador,
            o.local as Obra,
            strftime('%Y-%m', t.data) as Mes,
            COUNT(DISTINCT t.data) as Dias_Trabalhados,
            SUM(t.total_horas) as Total_Horas,
            AVG(t.total_horas) as Media_Horas_Dia
        FROM tarefas t
        JOIN colaboradores col ON t.colaborador_id = col.id
        JOIN obras o ON t.obra_id = o.id
        WHERE t.ativo = 1
            AND t.data BETWEEN ? AND ?
        GROUP BY col.nome, o.local, strftime('%Y-%m', t.data)
        ORDER BY col.nome, Mes
        """
    
    else:  # Resumo Mensal
        query = """
        SELECT 
            strftime('%Y-%m', t.data) as Mes,
            COUNT(DISTINCT t.colaborador_id) as Total_Colaboradores,
            COUNT(DISTINCT t.obra_id) as Total_Obras,
            COUNT(DISTINCT t.data) as Dias_Trabalhados,
            SUM(t.total_horas) as Total_Horas,
            AVG(t.total_horas) as Media_Horas_Dia
        FROM tarefas t
        WHERE t.ativo = 1
            AND t.data BETWEEN ? AND ?
        GROUP BY strftime('%Y-%m', t.data)
        ORDER BY Mes
        """
    
    df = pd.read_sql_query(
        query,
        conn,
        params=(data_inicio.strftime('%Y-%m-%d'),
                data_fim.strftime('%Y-%m-%d'))
    )
    
    if not df.empty:
        st.subheader(f"Relatório: {tipo_relatorio}")
        st.dataframe(df)
        
        # Gerar visualização adequada para cada tipo de relatório
        if tipo_relatorio in ["Horas por Colaborador", "Horas por Obra", "Horas por Contratante"]:
            fig = px.bar(
                df,
                x=df.columns[0],  # Primeira coluna (identificador)
                y='Total_Horas',
                title=f'Total de Horas - {tipo_relatorio}'
            )
            st.plotly_chart(fig)
        
        elif tipo_relatorio == "Produtividade":
            fig = px.line(
                df,
                x='Mes',
                y='Media_Horas_Dia',
                color='Colaborador',
                title='Evolução da Produtividade por Colaborador'
            )
            st.plotly_chart(fig)
        
        else:  # Resumo Mensal
            fig = px.line(
                df,
                x='Mes',
                y=['Total_Horas', 'Media_Horas_Dia'],
                title='Evolução Mensal'
            )
            st.plotly_chart(fig)
        
        # Opção para download do relatório
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

# Função para configurações
def configuracoes():
    st.title("Configurações")
    
    if st.session_state.username == "adm":
        st.subheader("Configurações do Sistema")
        
        # Backup do banco de dados
        if st.button("Fazer Backup do Banco de Dados"):
            try:
                data_atual = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_file = f"backup_timesheet_{data_atual}.db"
                
                conn = sqlite3.connect('timesheet.db')
                backup = sqlite3.connect(backup_file)
                conn.backup(backup)
                backup.close()
                conn.close()
                
                # Preparar o arquivo para download
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
        
        # Restaurar backup
        uploaded_file = st.file_uploader("Restaurar Backup", type=['db'])
        if uploaded_file is not None:
            if st.button("Restaurar Banco de Dados"):
                try:
                    # Criar backup do banco atual antes de restaurar
                    data_atual = datetime.now().strftime("%Y%m%d_%H%M%S")
                    backup_atual = f"backup_antes_restauracao_{data_atual}.db"
                    
                    conn_atual = sqlite3.connect('timesheet.db')
                    backup = sqlite3.connect(backup_atual)
                    conn_atual.backup(backup)
                    backup.close()
                    conn_atual.close()
                    
                    # Restaurar o banco enviado
                    with open('timesheet.db', 'wb') as f:
                        f.write(uploaded_file.getbuffer())
                    
                    st.success("Banco de dados restaurado com sucesso!")
                    st.warning("O sistema será reiniciado.")
                    time.sleep(3)
                    st.experimental_rerun()
                except Exception as e:
                    st.error(f"Erro ao restaurar banco de dados: {str(e)}")
    
    # Configurações do usuário
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
            
            # Verificar senha atual
            senha_hash = hashlib.sha256(senha_atual.encode()).hexdigest()
            c.execute("SELECT id FROM usuarios WHERE username = ? AND password = ?",
                     (st.session_state.username, senha_hash))
            
            if c.fetchone() is None:
                st.error("Senha atual incorreta!")
            else:
                # Atualizar senha
                nova_senha_hash = hashlib.sha256(nova_senha.encode()).hexdigest()
                c.execute("UPDATE usuarios SET password = ? WHERE username = ?",
                         (nova_senha_hash, st.session_state.username))
                conn.commit()
                st.success("Senha alterada com sucesso!")
            
            conn.close()

if __name__ == "__main__":
    main()
