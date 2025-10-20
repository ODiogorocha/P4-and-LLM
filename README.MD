# Detecção de Anomalias em Redes Utilizando P4 e Modelos de Linguagem
Este repositório apresenta uma solução inovadora para detecção de anomalias em redes, integrando switches programáveis P4 com Modelos de Linguagem de Grande Escala (LLMs). O projeto explora o potencial de SDN e inteligência artificial para monitorar, analisar e mitigar comportamentos suspeitos em ambientes simulados.

---

## 1. Contexto e Motivação

Com o crescimento do tráfego de rede e a complexidade dos ataques cibernéticos, torna-se essencial adotar abordagens flexíveis e inteligentes para defesa e monitoramento. Switches programáveis P4 oferecem controle granular e visibilidade em tempo real, enquanto LLMs possibilitam análise contextual avançada, identificando padrões anômalos que métodos tradicionais não detectam. Este projeto demonstra como a integração dessas tecnologias pode aprimorar a segurança de redes.

---

## 2. Arquitetura do Sistema

A solução é composta por quatro camadas principais:

1. **Infraestrutura de Rede (Mininet + P4 BMv2)**
    - Simulação de topologia SDN.
    - Switches P4 para coleta e encaminhamento de dados de fluxo.

2. **Programa P4 (`flow_collector.p4`)**
    - Extração de cabeçalhos de pacotes.
    - Geração de relatórios de fluxo (digests) para o controlador.
    - Tabelas ACL para bloqueio dinâmico de tráfego.

3. **Controlador Python**
    - Recebe e processa dados dos switches.
    - Interage com o módulo LLM para análise e classificação de tráfego.
    - Aplica políticas de mitigação, como bloqueio de IPs maliciosos via P4Runtime.

4. **Módulo LLM (Simulado)**
    - Analisa dados recebidos do controlador.
    - Detecta anomalias e sugere ações de resposta.

### Fluxo Operacional

1. Pacotes trafegam pela topologia simulada.
2. O programa P4 coleta informações e envia ao controlador.
3. O controlador processa os dados e consulta a LLM.
4. A LLM identifica anomalias e recomenda ações.
5. O controlador aplica regras de mitigação nos switches.

---

## 3. Execução da Simulação

### Requisitos

- Python 3.10+
- Bibliotecas listadas em `requirements.txt`

### Passos

1. Clone o repositório:
    ```bash
    git clone https://github.com/usuario/P4-and-LLM.git
    cd P4-and-LLM
    ```

2. Instale as dependências:
    ```bash
    # Detecção de Anomalias em Redes Utilizando P4 e Modelos de Linguagem

    Este repositório demonstra uma solução para detecção de anomalias em redes, integrando
    programabilidade P4 com Modelos de Linguagem (LLMs). O código inclui um controlador
    simulado que coleta fluxos gerados artificialmente, envia-os para uma LLM (real ou
    simulada) e aplica ações de mitigação (ex.: drop) no P4 (simulado).

    ---

    ## Estrutura principal

    - `src/class/controller.py`  — Controlador principal (classe `Controller`).
    - `src/mininet_setup.py`    — Classe `MininetSimulator` que inicia o `controller.py` como subprocesso.
    - `src/main.py`             — Runner central que pode executar em `subprocess` ou `inprocess`.
    - `src/flow_collector.p4`   — Programa P4 (coleta de fluxos) — (se aplicável).
    - `src/requirements.txt`    — Dependências Python.

    ---

    ## Como executar

    Primeiro, instale as dependências:

    ```bash
    pip install -r src/requirements.txt
    ```

    Existem dois modos principais para rodar a simulação (via `src/main.py`):

    1) Modo `subprocess` (padrão)

    Este modo usa a classe `MininetSimulator` para iniciar `controller.py` como um subprocesso.

    ```bash
    python3 src/main.py --mode subprocess --duration 60
    ```

    2) Modo `inprocess`

    Este modo carrega a classe `Controller` diretamente (do arquivo `src/class/controller.py`) e a executa
    em um processo separado usando `multiprocessing`. Útil para injetar clientes LLM diretamente.

    ```bash
    python3 src/main.py --mode inprocess --duration 60 --provider openai --api-key YOUR_KEY
    ```

    Parâmetros úteis:
    - `--duration`: duração da simulação em segundos (padrão 60).
    - `--controller-path`: caminho para `controller.py` (apenas para `subprocess`).
    - `--provider` / `--api-key`: usado no modo `inprocess` para inicializar um cliente LLM automaticamente.

    ---

    ## Injetando diferentes clientes LLM

    A classe `Controller` aceita um parâmetro `client` já instanciado, ou `provider`+`api_key`.
    Dessa forma você pode injetar qualquer cliente que siga um dos formatos mais comuns:

    - OpenAI-like: `client.chat.completions.create(...)`
    - Llama-like: `client.chat.create(...)` ou `client.completions.create(...)`
    - Callable simples: `client(prompt)`
    - Outros métodos comuns: `client.generate(prompt)`, `client.predict(prompt)`

    Exemplo (injetando um cliente chamável de teste):

    ```python
    from src.class.controller import Controller

    def dummy_client(prompt: str) -> dict:
        # Implementação de teste que devolve um dict compatível
        return {"anomaly_detected": False, "description": "Teste", "action": "none"}

    ctrl = Controller(client=dummy_client)
    print(ctrl.call_llm_for_anomaly_detection({"packet_count": 1, "byte_count": 100, "src_ip": "10.0.0.5"}))
    ```

    ---

    ## Notas finais

    - O fallback heurístico local detecta anomalia quando `packet_count > 5` ou `byte_count > 8000`.
    - Os comentários do código foram traduzidos para PT-BR para facilitar a leitura.
    - Se quiser que eu gere um exemplo pronto que injete um cliente real (por exemplo, `openai` ou `llama`), diga qual cliente você usa e eu adiciono um exemplo de configuração.

    ---

    ## Referências

    - `docs/arquitetura.md`


