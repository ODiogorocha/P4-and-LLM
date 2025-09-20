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
    pip install -r requirements.txt
    ```

3. Execute a simulação:
    ```bash
    python3 mininet_setup.py
    ```

O controlador iniciará a coleta de fluxos simulados, enviará os dados ao módulo LLM e aplicará regras de mitigação conforme as recomendações.

---

## 4. Referências e Documentação

- [Documentação da arquitetura](docs/arquitetura.md)


