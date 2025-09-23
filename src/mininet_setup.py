import os
import time
import subprocess

# Caminho para o controlador Python
CONTROLLER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "controller.py")

def run_simulation():
    print("*** Iniciando o controlador simulado em segundo plano (sem Mininet real) ***\n")
    # Inicia o controlador Python simulado em segundo plano
    controller_process = subprocess.Popen(["python3", CONTROLLER_PATH])

    print("*** Controlador simulado em execução. A simulação será executada por 30 segundos. ***\n")
    try:
        # Manter o processo principal ativo por um tempo para que o controlador simulado possa rodar
        time.sleep(30)
    finally:
        print("\n*** Tempo de simulação esgotado. Terminando o controlador simulado... ***\n")
        controller_process.terminate()
        controller_process.wait()
        print("*** Controlador simulado terminado. ***\n")

if __name__ == "__main__":
    run_simulation()

