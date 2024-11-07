import tkinter as tk
from tkinter import ttk, messagebox
from cryptography.fernet import Fernet
from pymongo import MongoClient
import bcrypt

chave = Fernet.generate_key()
fernet = Fernet(chave)

uri = "mongodb+srv://mariaducpaulino:1234567ABCD@projetinhobruno.v3hzt.mongodb.net/?retryWrites=true&w=majority&appName=projetinhoBruno"
client = MongoClient(uri)
db = client['projetoBD']
colecaoRegistros = db['registrosMedicos']
colecaoProfissionais = db['profissionais']

def criptografar(dado):
    return fernet.encrypt(dado.encode())

def descriptografar(dado):
    return fernet.decrypt(dado).decode()

def cadastrar_medico():
    nome = entry_nome_cadastro.get().strip()
    senha = entry_senha_cadastro.get().strip()

    if any(char.isdigit() for char in nome):
        messagebox.showwarning("Atenção", "O nome do médico não pode conter números.")
        return

    if not nome or not senha:
        messagebox.showwarning("Atenção", "Por favor, preencha ambos os campos: nome e senha.")
        return

    hashed_senha = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())
    hashed_nome = bcrypt.hashpw(senha.encode(), bcrypt.gensalt())
    colecaoProfissionais.insert_one({
        "Nome do profissional": hashed_nome,
        "Senha do profissional": hashed_senha
    })
    messagebox.showinfo("Sucesso", "Cadastro realizado com sucesso!")
    entry_nome_cadastro.delete(0, tk.END)
    entry_senha_cadastro.delete(0, tk.END)

def autenticar():
    global medico_autenticado
    nome = entry_nome_login.get().strip()
    senha = entry_senha_login.get().strip()

    if not nome or not senha:
        messagebox.showwarning("Atenção", "Por favor, preencha ambos os campos: nome e senha.")
        return

    profissional = colecaoProfissionais.find_one({"Nome do profissional": nome})
    if profissional and bcrypt.checkpw(senha.encode(), profissional["Senha do profissional"]):
        medico_autenticado = True
        messagebox.showinfo("Sucesso", "Login realizado com sucesso!")
        entry_nome_login.delete(0, tk.END)
        entry_senha_login.delete(0, tk.END)

        notebook.tab(2, state="normal")
        notebook.tab(3, state="normal")
    else:
        messagebox.showwarning("Erro", "Nome ou senha incorretos.")

def cadastrar_paciente():
    if not medico_autenticado:
        messagebox.showwarning("Atenção", "Você precisa se autenticar antes de registrar pacientes.")
        return

    nome = entry_nome_paciente.get().strip()
    id_paciente = entry_id_paciente.get().strip()
    historico = entry_historico.get().strip()
    tratamentos = entry_tratamentos.get().strip()

    if not nome or not id_paciente:
        messagebox.showwarning("Atenção", "Por favor, preencha os campos obrigatórios: nome e ID do paciente.")
        return

    paciente_existente = colecaoRegistros.find_one({"id do paciente": id_paciente})
    if paciente_existente:
        messagebox.showwarning("Atenção", "ID do paciente já registrado. Por favor, insira um ID único.")
        return

    nome_criptografado = criptografar(nome)
    historico_criptografado = criptografar(historico)
    tratamentos_criptografado = criptografar(tratamentos)

    colecaoRegistros.insert_one({
        "id do paciente": id_paciente,
        "Nome do paciente": nome_criptografado,
        "Histórico do paciente": historico_criptografado,
        "Tratamentos do paciente": tratamentos_criptografado
    })
    messagebox.showinfo("Sucesso", "Cadastro de paciente realizado com sucesso.")
    entry_nome_paciente.delete(0, tk.END)
    entry_id_paciente.delete(0, tk.END)
    entry_historico.delete(0, tk.END)
    entry_tratamentos.delete(0, tk.END)

def consultar_paciente():
    id_paciente = entry_consulta_id.get().strip()
    if not id_paciente:
        messagebox.showwarning("Atenção", "Por favor, preencha o ID do paciente para consulta.")
        return

    paciente = colecaoRegistros.find_one({"id do paciente": id_paciente})

    if paciente:
        nome = descriptografar(paciente["Nome do paciente"])
        historico = descriptografar(paciente["Histórico do paciente"])
        tratamentos = descriptografar(paciente["Tratamentos do paciente"])
        messagebox.showinfo("Dados do Paciente",
                            f"Nome: {nome}\nHistórico: {historico}\nTratamentos: {tratamentos}")
    else:
        messagebox.showwarning("Erro", "Paciente não encontrado.")

root = tk.Tk()
root.title("Sistema de gerenciamento de registros médicos")
root.geometry("500x400")

notebook = ttk.Notebook(root)
notebook.pack(expand=True, fill='both')

aba_cadastro = ttk.Frame(notebook)
notebook.add(aba_cadastro, text="Cadastro Médico")

tk.Label(aba_cadastro, text="Nome do Médico:").pack(pady=5)
entry_nome_cadastro = tk.Entry(aba_cadastro)
entry_nome_cadastro.pack()

tk.Label(aba_cadastro, text="Senha:").pack(pady=5)
entry_senha_cadastro = tk.Entry(aba_cadastro, show="*")
entry_senha_cadastro.pack()

btn_cadastrar = tk.Button(aba_cadastro, text="Cadastrar", command=cadastrar_medico)
btn_cadastrar.pack(pady=10)

aba_login = ttk.Frame(notebook)
notebook.add(aba_login, text="Login Médico")

tk.Label(aba_login, text="Nome do Médico:").pack(pady=5)
entry_nome_login = tk.Entry(aba_login)
entry_nome_login.pack()

tk.Label(aba_login, text="Senha:").pack(pady=5)
entry_senha_login = tk.Entry(aba_login, show="*")
entry_senha_login.pack()

btn_login = tk.Button(aba_login, text="Login", command=autenticar)
btn_login.pack(pady=10)

aba_registro_paciente = ttk.Frame(notebook)
notebook.add(aba_registro_paciente, text="Registro Paciente")
notebook.tab(2, state="disabled")

tk.Label(aba_registro_paciente, text="Nome do Paciente:").pack(pady=5)
entry_nome_paciente = tk.Entry(aba_registro_paciente)
entry_nome_paciente.pack()

tk.Label(aba_registro_paciente, text="ID do Paciente:").pack(pady=5)
entry_id_paciente = tk.Entry(aba_registro_paciente)
entry_id_paciente.pack()

tk.Label(aba_registro_paciente, text="Histórico:").pack(pady=5)
entry_historico = tk.Entry(aba_registro_paciente)
entry_historico.pack()

tk.Label(aba_registro_paciente, text="Tratamentos:").pack(pady=5)
entry_tratamentos = tk.Entry(aba_registro_paciente)
entry_tratamentos.pack()

btn_cadastrar_paciente = tk.Button(aba_registro_paciente, text="Cadastrar Paciente", command=cadastrar_paciente)
btn_cadastrar_paciente.pack(pady=10)

aba_consulta_paciente = ttk.Frame(notebook)
notebook.add(aba_consulta_paciente, text="Consulta Paciente")
notebook.tab(3, state="disabled")

tk.Label(aba_consulta_paciente, text="ID do Paciente:").pack(pady=5)
entry_consulta_id = tk.Entry(aba_consulta_paciente)
entry_consulta_id.pack()

btn_consultar_paciente = tk.Button(aba_consulta_paciente, text="Consultar", command=consultar_paciente, )
btn_consultar_paciente.pack(pady=10)

medico_autenticado = False

root.mainloop()
