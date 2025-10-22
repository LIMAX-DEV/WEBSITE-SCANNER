import time
import sys
import random
import os
import datetime

try:
    import colorama
    import requests
except Exception as e:
    print(f'Required modules not installed. Error: {e}')
    sys.exit(1)

color = colorama.Fore
RED = color.RED
WHITE = color.WHITE
GREEN = color.GREEN
RESET = color.RESET
BLUE = color.BLUE
YELLOW = color.YELLOW

# Definir cores em azul escuro
DARK_BLUE = "\033[34m"  # Azul escuro
BLUE = color.BLUE        # Azul padrão

# Atualizar os prefixos/sufixos para azul escuro
BEFORE = f'{DARK_BLUE}[{WHITE}+{DARK_BLUE}]{RESET}'
BEFORE_GREEN = f'{DARK_BLUE}[{WHITE}+{DARK_BLUE}]{RESET}'
BEFORE_DARK_BLUE = f'{DARK_BLUE}[{WHITE}+{DARK_BLUE}]{RESET}'
AFTER = f'{DARK_BLUE}>{RESET}'
AFTER_GREEN = f'{DARK_BLUE}>{RESET}'
AFTER_DARK_BLUE = f'{DARK_BLUE}>{RESET}'

# Atualizar ícones/status para azul escuro
INFO = f'{DARK_BLUE}i{RESET}'
INPUT = f'{DARK_BLUE}?{RESET}'
WAIT = f'{DARK_BLUE}*{RESET}'
ERROR = f'{DARK_BLUE}!{RESET}'
ADD = f'{DARK_BLUE}+{RESET}'
GEN_VALID = f'{DARK_BLUE}√{RESET}'

def Title(title):
    """Exibe um título formatado"""
    width = 60
    print(f"\n{DARK_BLUE}{'=' * width}{RESET}")
    print(f"{DARK_BLUE}{title.center(width)}{RESET}")
    print(f"{DARK_BLUE}{'=' * width}{RESET}\n")

def Slow(text):
    """Exibe texto letra por letra"""
    for char in text:
        print(char, end='', flush=True)
        time.sleep(0.01)
    print()

def current_time_hour():
    """Retorna a hora atual formatada"""
    return datetime.datetime.now().strftime('%H:%M:%S')

def ChoiceUserAgent():
    """Seleciona um User-Agent aleatório"""
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/119.0",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/119.0.0.0"
    ]
    return random.choice(user_agents)

def Censored(text):
    """Função para censurar texto (placeholder)"""
    return text

def Continue():
    """Pausa e espera Enter para continuar"""
    input(f"\n{BEFORE + current_time_hour() + AFTER} {INPUT} Press Enter to continue...{RESET}")

def Reset():
    """Limpa a tela do terminal"""
    os.system('cls' if os.name == 'nt' else 'clear')

def Error(e):
    """Exibe mensagem de erro"""
    print(f"\n{BEFORE + current_time_hour() + AFTER} {ERROR} Error: {WHITE}{e}{RESET}")
    Continue()

def ErrorModule(e):
    """Exibe erro de módulo faltante"""
    print(f"\n{BEFORE + current_time_hour() + AFTER} {ERROR} Module Error: {WHITE}{e}{RESET}")
    print(f"{BEFORE + current_time_hour() + AFTER} {INFO} Install required modules: {WHITE}pip install -r requirements.txt{RESET}")
    sys.exit(1)

def print_success(message):
    """Exibe mensagem de sucesso"""
    print(f"{BEFORE_GREEN + current_time_hour() + AFTER_GREEN} {GEN_VALID} {message}")

def print_error(message):
    """Exibe mensagem de erro"""
    print(f"{BEFORE + current_time_hour() + AFTER} {ERROR} {message}")

def print_info(message):
    """Exibe mensagem informativa"""
    print(f"{BEFORE + current_time_hour() + AFTER} {INFO} {message}")

def print_wait(message):
    """Exibe mensagem de espera"""
    print(f"{BEFORE + current_time_hour() + AFTER} {WAIT} {message}")

def print_add(message):
    """Exibe mensagem de adição"""
    print(f"{BEFORE + current_time_hour() + AFTER} {ADD} {message}")