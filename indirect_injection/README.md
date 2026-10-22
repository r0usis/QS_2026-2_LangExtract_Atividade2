# Execução do teste

No diretório do projeto, crie e ative o ambiente virtual:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Instale as dependências:

```bash
pip install -r requirements.txt
```

Com o [Ollama](https://ollama.com/) instalado e em execução, baixe o modelo utilizado pelo teste:

```bash
ollama pull gemma2:2b
```

Execute o script:

```bash
python3 test_langextract_injection.py
```

Ao final, o relatório será salvo no arquivo `evidencias_testes.json`.
