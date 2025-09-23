import time
import random
import os
import json
from openai import OpenAI

# Inicializa o cliente OpenAI com a chave da API
# Certifique-se de que OPENAI_API_KEY está definida como uma variável de ambiente
client = OpenAI(api_key=os.environ.get("OPENAI_API_KEY"))

def call_openai_for_anomaly_detection(flow_data):
    prompt = f"""Analise os seguintes dados de fluxo de rede para detectar anomalias. 
    Os dados de fluxo são: {flow_data}.
    Identifique se há alguma anomalia (por exemplo, alto volume de pacotes de um único IP de origem, varredura de porta, etc.).
    Se uma anomalia for detectada, sugira uma ação de mitigação, como 'drop' para um IP de origem específico.
    Formato da resposta JSON esperado: 
    {{"anomaly_detected": boolean, "description": "string", "action": "none" | "drop", "target_ip": "string" (se a ação for 'drop')}}
    Exemplo de anomalia: {{"anomaly_detected": true, "description": "Alto volume de tráfego do IP 10.0.0.1, possível ataque DDoS.", "action": "drop", "target_ip": "10.0.0.1"}}
    Exemplo sem anomalia: {{"anomaly_detected": false, "description": "Nenhuma anomalia detectada.", "action": "none"}}
    """

    try:
        response = client.chat.completions.create(
            model="gpt-3.5-turbo",  
            messages=[
                {"role": "system", "content": "Você é um analista de segurança de rede especializado em detectar anomalias de tráfego."},
                {"role": "user", "content": prompt}
            ],
            response_format={ "type": "json_object" },
            temperature=0.2, # Baixa temperatura para respostas mais consistentes
        )
        # A resposta da API já deve ser um objeto JSON devido a response_format
        return response.choices[0].message.content
    except Exception as e:
        print(f"Erro ao chamar a API da OpenAI: {e}")
        return None

# Função para simular a LLM (agora chama a API real)
def simulate_llm_anomaly_detection(flow_data):
    print(f"[LLM] Enviando dados de fluxo para a API da OpenAI para análise: {flow_data}")
    openai_response = call_openai_for_anomaly_detection(flow_data)

    if openai_response:
        try:
            parsed_response = json.loads(openai_response)
            print(f"[LLM] Resposta da OpenAI: {parsed_response}")
            if parsed_response.get("anomaly_detected") and parsed_response.get("action") == "drop":
                return {"action": "drop", "src_ip": parsed_response.get("target_ip")}
            else:
                return {"action": "none"}
        except json.JSONDecodeError as e:
            print(f"Erro ao decodificar JSON da resposta da OpenAI: {e}")
            return {"action": "none"}
    return {"action": "none"}

# Função para simular a aplicação de regras no switch P4
def simulate_p4_rule_application(table_name, match_fields, action_name, action_params={}):
    print(f"[P4Runtime Simulado] Aplicando regra na tabela \'{table_name}\':")
    print(f"  Match: {match_fields}")
    print(f"  Action: {action_name} com parâmetros {action_params}")
    print("[P4Runtime Simulado] Regra aplicada com sucesso (simulado).")

# Função principal do controlador (simulado)
def run_simulated_controller():
    print("Controlador simulado iniciado. Gerando e analisando dados de fluxo...")

    # Simular a configuração inicial do pipeline P4 (apenas para fins de log)
    print("[Controlador Simulado] Pipeline P4 configurado (simulado).")
    print("[Controlador Simulado] Digest configurado (simulado).")

    flow_id = 0
    while True:
        flow_id += 1
        # Simular coleta de dados de fluxo (que em um cenário real viria do switch via digest)
        # Gerar dados de fluxo aleatórios, com um IP "malicioso" ocasional
        src_ip_prefix = "10.0.0."
        dst_ip_prefix = "10.0.0."

        # Simular um IP malicioso (10.0.0.1) com mais frequência para teste
        if random.random() < 0.3: # 30% de chance de ser o IP malicioso
            src_ip = "10.0.0.1"
            packet_count = random.randint(6, 20) # Alto volume
        else:
            src_ip = src_ip_prefix + str(random.randint(2, 254))
            packet_count = random.randint(1, 5) # Volume normal

        dst_ip = dst_ip_prefix + str(random.randint(2, 254))
        src_port = random.randint(1024, 65535)
        dst_port = random.choice([80, 443, 22, 23, 53, 8080])
        protocol = random.choice([6, 17]) # TCP (6) ou UDP (17)
        byte_count = packet_count * random.randint(64, 1500)

        simulated_flow_data = {
            "flow_id": flow_id,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "protocol": protocol,
            "packet_count": packet_count,
            "byte_count": byte_count
        }

        print(f"\n[Controlador Simulado] Gerado dados de fluxo: {simulated_flow_data}")

        # 4. Enviar dados para a LLM simulada
        llm_response = simulate_llm_anomaly_detection(simulated_flow_data)

        # 5. Processar resposta da LLM e aplicar ações (simulado)
        if llm_response["action"] == "drop":
            print(f"[Controlador Simulado] LLM recomendou DROPAR tráfego do IP: {llm_response['src_ip']}")
            # Simular a aplicação da regra de drop na tabela ACL do P4
            simulate_p4_rule_application("acl_table", {"hdr.ipv4.srcAddr": llm_response['src_ip']}, "_drop")

        time.sleep(2) # Simula intervalo de coleta e análise

if __name__ == "__main__":
    run_simulated_controller()
