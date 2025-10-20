import requests
import os
import time
import random
import json
from typing import Any, Optional

try:
    from openai import OpenAI  # type: ignore
except Exception:
    OpenAI = None  # type: ignore


class Controller:
    """Controlador simulado que usa uma LLM para detectar anomalias em fluxos de rede.

    O Controller aceita um `client` já instanciado, ou tentará inicializar um cliente
    OpenAI quando `provider='openai'` e uma `api_key` for fornecida. Se nenhum cliente
    estiver disponível, é usado um heurístico local simples.
    """

    def __init__(self, client: Optional[Any] = None, api_key: Optional[str] = None, provider: Optional[str] = None):
    # Usa o cliente injetado, se fornecido
        if client is not None:
            self.client = client
            print("Usando cliente LLM injetado.")
            return

    # Tenta inicializar automaticamente o cliente OpenAI se solicitado
        if provider == 'openai' and api_key and OpenAI is not None:
            try:
                self.client = OpenAI(api_key=api_key)
                print("Cliente OpenAI inicializado a partir de provider+api_key.")
                return
            except Exception as e:
                print(f"Erro ao inicializar OpenAI client: {e}")

    # Nenhum cliente disponível -> usar heurístico local como fallback
        self.client = None
        if provider and api_key:
            print(f"Provider '{provider}' informado, mas não foi possível inicializar o client — usando simulador local.")
        else:
            print("Nenhum cliente LLM fornecido — usando simulador local de LLM.")

    def call_llm_for_anomaly_detection(self, flow_data: dict) -> Optional[str]:
        """Gera o prompt a partir de `flow_data` e chama o cliente LLM configurado.

        Retorna uma string JSON (preferível) ou None em caso de erro.
        """
        prompt = (
            f"Analise os seguintes dados de fluxo de rede para detectar anomalias.\n"
            f"Os dados de fluxo são: {flow_data}.\n"
            "Identifique se há alguma anomalia (por exemplo, alto volume de pacotes de um único IP de origem, varredura de porta, etc.).\n"
            "Se uma anomalia for detectada, sugira uma ação de mitigação, como 'drop' para um IP de origem específico.\n"
            "Formato da resposta JSON esperado: {\"anomaly_detected\": boolean, \"description\": \"string\", \"action\": \"none\" | \"drop\", \"target_ip\": \"string\"}\n"
        )

    # Heurístico de fallback quando nenhum cliente está configurado
        if self.client is None:
            pkt_count = flow_data.get("packet_count", 0)
            byte_count = flow_data.get("byte_count", 0)
            src_ip = flow_data.get("src_ip", "")
            if pkt_count > 5 or byte_count > 8000:
                simulated = {
                    "anomaly_detected": True,
                    "description": f"Alto volume de tráfego do IP {src_ip}",
                    "action": "drop",
                    "target_ip": src_ip,
                }
            else:
                simulated = {"anomaly_detected": False, "description": "Nenhuma anomalia detectada.", "action": "none"}
            return json.dumps(simulated)

    # Lógica genérica de chamada do cliente para suportar diferentes formatos de cliente LLM
        try:
            client = self.client

            # 1) Estilo OpenAI: client.chat.completions.create(...)
            if hasattr(client, 'chat') and hasattr(getattr(client, 'chat'), 'completions'):
                fn = client.chat.completions.create
                resp = fn(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": "Você é um analista de segurança de rede especializado em detectar anomalias de tráfego."},
                        {"role": "user", "content": prompt},
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.2,
                )
                # normaliza a resposta
                if isinstance(resp, dict):
                    return json.dumps(resp)
                if hasattr(resp, 'choices'):
                    try:
                        return resp.choices[0].message.content
                    except Exception:
                        return str(resp)

            # 2) Estilo Llama: client.chat.create(...) ou client.completions.create(...)
            if hasattr(client, 'chat') and hasattr(getattr(client, 'chat'), 'create'):
                resp = client.chat.create(model='Llama', messages=[{"role": "user", "content": prompt}])
                if isinstance(resp, dict):
                    return json.dumps(resp)
                return getattr(resp, 'content', str(resp))

            if hasattr(client, 'completions') and hasattr(getattr(client, 'completions'), 'create'):
                resp = client.completions.create(model='Llama', prompt=prompt)
                if isinstance(resp, dict):
                    return json.dumps(resp)
                return getattr(resp, 'text', str(resp))

            # 3) Se o client for chamável (callable), chama com o prompt
            if callable(client):
                resp = client(prompt)
                if isinstance(resp, dict):
                    return json.dumps(resp)
                return str(resp)

            # 4) Métodos fallback comuns
            if hasattr(client, 'generate'):
                resp = client.generate(prompt)
                if isinstance(resp, dict):
                    return json.dumps(resp)
                return str(resp)
            if hasattr(client, 'predict'):
                resp = client.predict(prompt)
                if isinstance(resp, dict):
                    return json.dumps(resp)
                return str(resp)

            print("Formato de cliente desconhecido — não foi possível chamar o LLM.")
            return None
        except Exception as e:
            print(f"Erro ao chamar o cliente LLM: {e}")
            return None

    def simulate_llm_anomaly_detection(self, flow_data: dict) -> dict:
        """Chama a LLM (real ou simulada) e normaliza a resposta para {'action': ..., 'src_ip': ...}.
        """
        print(f"[LLM] Enviando dados de fluxo para análise: {flow_data}")
        llm_response = self.call_llm_for_anomaly_detection(flow_data)

        if llm_response:
            try:
                parsed_response = json.loads(llm_response) if isinstance(llm_response, str) else llm_response
                print(f"[LLM] Resposta: {parsed_response}")
                if parsed_response.get("anomaly_detected") and parsed_response.get("action") == "drop":
                    return {"action": "drop", "src_ip": parsed_response.get("target_ip")}
                else:
                    return {"action": "none"}
            except (json.JSONDecodeError, TypeError) as e:
                print(f"Erro ao decodificar JSON da resposta da LLM: {e}")
                return {"action": "none"}
        return {"action": "none"}

    def simulate_p4_rule_application(self, table_name: str, match_fields: dict, action_name: str, action_params: Optional[dict] = None) -> None:
        if action_params is None:
            action_params = {}
        print(f"[P4Runtime Simulado] Aplicando regra na tabela '{table_name}':")
        print(f"  Match: {match_fields}")
        print(f"  Action: {action_name} com parâmetros {action_params}")
        print("[P4Runtime Simulado] Regra aplicada com sucesso (simulado).")

    def run_simulated_controller(self) -> None:
        print("Controlador simulado iniciado. Gerando e analisando dados de fluxo...")
        print("[Controlador Simulado] Pipeline P4 configurado (simulado).")
        print("[Controlador Simulado] Digest configurado (simulado).")

        flow_id = 0
        while True:
            flow_id += 1
            src_ip_prefix = "10.0.0."
            dst_ip_prefix = "10.0.0."

            if random.random() < 0.3:
                src_ip = "10.0.0.1"
                packet_count = random.randint(6, 20)
            else:
                src_ip = src_ip_prefix + str(random.randint(2, 254))
                packet_count = random.randint(1, 5)

            dst_ip = dst_ip_prefix + str(random.randint(2, 254))
            src_port = random.randint(1024, 65535)
            dst_port = random.choice([80, 443, 22, 23, 53, 8080])
            protocol = random.choice([6, 17])
            byte_count = packet_count * random.randint(64, 1500)

            simulated_flow_data = {
                "flow_id": flow_id,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "src_port": src_port,
                "dst_port": dst_port,
                "protocol": protocol,
                "packet_count": packet_count,
                "byte_count": byte_count,
            }

            print(f"\n[Controlador Simulado] Gerado dados de fluxo: {simulated_flow_data}")

            llm_response = self.simulate_llm_anomaly_detection(simulated_flow_data)

            if llm_response.get("action") == "drop":
                print(f"[Controlador Simulado] LLM recomendou DROPAR tráfego do IP: {llm_response['src_ip']}")
                self.simulate_p4_rule_application("acl_table", {"hdr.ipv4.srcAddr": llm_response['src_ip']}, "_drop")

            time.sleep(2)


if __name__ == "__main__":
    api_key = os.environ.get("OPENAI_API_KEY")
    ctrl = Controller(api_key=api_key, provider='openai')
    ctrl.run_simulated_controller()
