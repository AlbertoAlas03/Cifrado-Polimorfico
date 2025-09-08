import hashlib
import socket
import pickle
import struct
import time

# -------------------- FUNCIONES DE GENERACIÓN DE CLAVES --------------------

def scramble_function(x, y):
    """
    Función de mezcla: combina dos valores con multiplicación y suma, 
    luego aplica XOR.
    """
    return (x * y) ^ (x + y)

def generation_function(P0, Q):
    """
    Genera una clave intermedia a partir de P0 y Q mediante suma, multiplicación y XOR.
    """
    return (P0 + Q) ^ (P0 * Q)

def mutation_function(S, Q):
    """
    Modifica el valor S utilizando Q, con suma y multiplicación seguidas de XOR.
    """
    return (S + Q) ^ (S * Q)

def generate_key_table(P, Q, S, num_keys):
    """
    Genera una tabla de claves a partir de P, Q y S.
    
    Args:
        P (int): Parámetro inicial.
        Q (int): Parámetro recibido del servidor.
        S (int): Semilla inicial.
        num_keys (int): Cantidad de claves a generar.
    
    Returns:
        list[int]: Lista de claves generadas (64 bits cada una).
    """
    key_table = []
    current_S = S
    for _ in range(num_keys):
        P0 = scramble_function(P, current_S)
        key = generation_function(P0, Q)
        key_table.append(key & 0xFFFFFFFFFFFFFFFF)  # Mantener 64 bits
        current_S = mutation_function(current_S, Q)
    return key_table

# -------------------- FUNCIONES REVERSIBLES DE CIFRADO --------------------

def reversible_function_xor(data, key):
    """Cifra un byte con XOR usando la clave."""
    return data ^ key

def reversible_function_rotate(data, key):
    """Rota los bits de un byte a la izquierda."""
    rotate_bits = key % 8
    return ((data << rotate_bits) | (data >> (8 - rotate_bits))) & 0xFF

def reversible_function_substitute(data, key):
    """Sustituye el byte según una tabla S-Box generada con la clave."""
    sbox = [(i + key) % 256 for i in range(256)]
    return sbox[data]

# Diccionarios para acceso rápido
REVERSIBLE_FUNCTIONS = {
    0: reversible_function_xor,
    1: reversible_function_rotate,
    2: reversible_function_substitute
}

REVERSE_FUNCTIONS = {  # No se usa en el cliente, pero está para referencia
    0: reversible_function_xor,
    1: lambda data, key: ((data >> (key % 8)) | (data << (8 - (key % 8)))) & 0xFF,
    2: lambda data, key: (data - key) % 256
}

# -------------------- FUNCIONES AUXILIARES --------------------

def calculate_psn(message, previous_psn):
    """
    Calcula el número de secuencia polimórfica (PSN) para un mensaje.
    """
    if previous_psn is None:
        return ord(message[0]) & 0x0F if message else 0
    index = previous_psn % len(message)
    return ord(message[index]) & 0x0F

def get_function_sequence(psn, num_functions=3):
    """
    Genera la secuencia de funciones reversibles a aplicar, según el PSN.
    """
    sequence = []
    temp_psn = psn
    for _ in range(num_functions):
        sequence.append(temp_psn % num_functions)
        temp_psn = (temp_psn >> 2) | ((temp_psn & 0x03) << 2)
    return sequence

def encrypt_message(message, key_table, psn):
    """
    Cifra un mensaje usando la tabla de claves y el PSN.
    
    Returns:
        list[int]: Lista de bytes cifrados.
    """
    encrypted_parts = []
    function_sequence = get_function_sequence(psn)
    
    for i, char in enumerate(message):
        key = key_table[(i + psn) % len(key_table)]
        encrypted_char = ord(char)
        
        for func_idx in function_sequence:
            encrypted_char = REVERSIBLE_FUNCTIONS[func_idx](encrypted_char, key)
        
        encrypted_parts.append(encrypted_char)
    
    return encrypted_parts

# -------------------- MENU INTERACTIVO --------------------

def mostrar_menu():
    """Muestra el menú principal y devuelve la opción seleccionada."""
    print("\n" + "="*50)
    print("        CIFRADO POLIMÓRFICO")
    print("="*50)
    print("1.  Enviar Mensaje Regular (RM)")
    print("2.  Actualizar Claves (KUM)")
    print("3.  Finalizar Conexión (LCM)")
    print("4.  Mostrar Estado Actual")
    print("5.  Salir")
    print("="*50)
    return input("Selecciona una opción (1-5): ")

# -------------------- PROGRAMA PRINCIPAL --------------------

def main():
    """
    Cliente de cifrado polimórfico.
    Se conecta al servidor, genera claves y permite enviar mensajes cifrados.
    """
    P = 15485863  # Número primo grande
    S = 123456789  # Semilla inicial
    num_keys = 30
    previous_psn = None
    key_table = None
    Q = None
    
    #configuracion del servidor
    server_ip = '172.16.0.2'
    server_port = 65432

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, server_port))
            print("✅ Conectado al servidor")
            
            # Paso 1: Enviar FCM (First Contact Message)
            print("Enviando FCM...")
            fcm_data = pickle.dumps(('FCM', P, S, num_keys))
            s.sendall(fcm_data)
            
            # Paso 2: Recibir Q del servidor
            response = pickle.loads(s.recv(1024))
            if response[0] == 'FCM_ACK':
                Q = response[1]
                key_table = generate_key_table(P, Q, S, num_keys)
                print(f"-- Tabla de claves generada ({len(key_table)} claves)")
                print(f"-- Q recibido: {Q}")
            
            # Menú interactivo
            while True:
                opcion = mostrar_menu()
                
                if opcion == '1':  # Enviar mensaje cifrado
                    mensaje = input("Ingresa el mensaje a cifrar: ")
                    if not mensaje:
                        print("Error, El mensaje no puede estar vacío")
                        continue
                    
                    psn = calculate_psn(mensaje, previous_psn)
                    encrypted_message = encrypt_message(mensaje, key_table, psn)
                    
                    rm_data = pickle.dumps(('RM', encrypted_message, psn))
                    s.sendall(rm_data)
                    print(f"-- Mensaje enviado con PSN: {psn}")
                    previous_psn = psn
                    time.sleep(1)
                
                elif opcion == '2':  # Actualizar claves
                    nueva_S = S + 1
                    kum_data = pickle.dumps(('KUM', nueva_S))
                    s.sendall(kum_data)
                    key_table = generate_key_table(P, Q, nueva_S, num_keys)
                    S = nueva_S
                    print(f"-- Claves actualizadas. Nueva S: {S}")
                    time.sleep(1)
                
                elif opcion == '3':  # Finalizar conexión
                    lcm_data = pickle.dumps(('LCM',))
                    s.sendall(lcm_data)
                    print("Conexión finalizada")
                    break
                
                elif opcion == '4':  # Mostrar estado
                    print("\nESTADO ACTUAL:")
                    print(f"   P: {P}")
                    print(f"   Q: {Q}")
                    print(f"   S: {S}")
                    print(f"   Claves generadas: {len(key_table) if key_table else 0}")
                    print(f"   Último PSN: {previous_psn}")
                    input("Presiona Enter para continuar...")
                
                elif opcion == '5':  # Salir
                    print("Saliendo...")
                    break
                
                else:
                    print("Opción no válida. Intenta de nuevo.")
    
    except ConnectionRefusedError:
        print("No se pudo conectar al servidor. Asegúrate de que decrypt.py esté ejecutándose.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
