import os
import time
import subprocess
from typing import Optional


# Caminho padrão para o controlador Python (arquivo controller.py na mesma pasta)
DEFAULT_CONTROLLER_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "controller.py")


class MininetSimulator:
    """Simulador mínimo que inicia o controlador simulado em segundo plano.

    Métodos:
        start() -> Inicia o processo do controlador em background e retorna o Popen.
        stop()  -> Termina o processo iniciado por start().
        run()   -> Ativa start(), espera `duration` segundos e então para o processo.
    """

    def __init__(self, controller_path: Optional[str] = None, duration: int = 60):
        self.controller_path = controller_path or DEFAULT_CONTROLLER_PATH
        self.duration = duration
        self._process: Optional[subprocess.Popen] = None

    def start(self) -> subprocess.Popen:
        """Inicia o controlador simulado em segundo plano.

        Retorna o objeto subprocess.Popen do processo iniciado.
        """
        print("*** Iniciando o controlador simulado em segundo plano (sem Mininet real) ***\n")
        # Inicia o controlador Python simulado em segundo plano
        self._process = subprocess.Popen(["python3", self.controller_path])
        print("*** Controlador simulado em execução. ***\n")
        return self._process

    def stop(self) -> None:
        """Termina o processo do controlador simulado iniciado por start()."""
        if self._process is None:
            print("Nenhum processo de controlador para terminar.")
            return

        print("\n*** Terminando o controlador simulado... ***\n")
        self._process.terminate()
        try:
            self._process.wait(timeout=10)
        except Exception:
            print("Processo não terminou a tempo; matando força (kill).")
            self._process.kill()
            self._process.wait()
        finally:
            print("*** Controlador simulado terminado. ***\n")
            self._process = None

    def run(self) -> None:
        """Executa a simulação completa: start() -> sleep(duration) -> stop()."""
        proc = self.start()
        try:
            print(f"*** A simulação será executada por {self.duration} segundos. ***\n")
            time.sleep(self.duration)
        finally:
            self.stop()


if __name__ == "__main__":
    sim = MininetSimulator()
    sim.run()