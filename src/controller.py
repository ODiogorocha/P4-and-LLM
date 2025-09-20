import time
import random
import socket

# Função para simular a LLM
def simulate_llm_anomaly_detection(flow_data):
    print(f"[LLM] Recebido dados de fluxo para análise: {flow_data}")
    # Lógica de detecção de anomalias simplificada
    # Se o IP de origem for 10.0.0.1 e o número de pacotes for alto (simulado aqui como > 5)
    if flow_data.get("src_ip") == "10.0.0.1" and flow_data.get("packet_count", 0) > 5:
        print("[LLM] Anomalia detectada: Tráfego do IP 10.0.0.1 é malicioso (alto volume).")
        return {"action": "drop", "src_ip": "10.0.0.1"}
    return {"action": "none"}

# Função para simular a aplicação de regras no switch P4
def simulate_p4_rule_application(table_name, match_fields, action_name, action_params={}):
    print(f"[P4Runtime Simulado] Aplicando regra na tabela '{table_name}':")
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

