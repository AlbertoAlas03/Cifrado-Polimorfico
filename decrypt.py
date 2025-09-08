import socket
import pickle

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
        Q (int): Parámetro fijo en el servidor.
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

# -------------------- FUNCIONES REVERSIBLES Y SU INVERSA --------------------

def reversible_function_xor(data, key):
    """Cifra/descifra un byte con XOR usando la clave."""
    return data ^ key

def reversible_function_rotate(data, key):
    """Rota los bits de un byte a la izquierda."""
    rotate_bits = key % 8
    return ((data << rotate_bits) | (data >> (8 - (key % 8)))) & 0xFF

def reversible_function_substitute(data, key):
    """Sustituye el byte según una tabla S-Box generada con la clave."""
    sbox = [(i + key) % 256 for i in range(256)]
    return sbox[data]

# Funciones reversibles
REVERSIBLE_FUNCTIONS = {
    0: reversible_function_xor,
    1: reversible_function_rotate,
    2: reversible_function_substitute
}

# Funciones inversas para descifrado
REVERSE_FUNCTIONS = {
    0: reversible_function_xor,
    1: lambda data, key: ((data >> (key % 8)) | (data << (8 - (key % 8)))) & 0xFF,
    2: lambda data, key: (data - key) % 256
}

# -------------------- FUNCIONES AUXILIARES --------------------

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

def decrypt_message(encrypted_parts, key_table, psn):
    """
    Descifra un mensaje usando la tabla de claves y el PSN.
    
    Args:
        encrypted_parts (list[int]): Lista de bytes cifrados.
        key_table (list[int]): Tabla de claves generada.
        psn (int): Número de secuencia polimórfica.
    
    Returns:
        str: Mensaje descifrado en texto plano.
    """
    decrypted_message = ""
    function_sequence = get_function_sequence(psn)
    reverse_sequence = list(reversed(function_sequence))  # Orden inverso para descifrar
    
    for i, encrypted_char in enumerate(encrypted_parts):
        key = key_table[(i + psn) % len(key_table)]
        decrypted_char = encrypted_char
        
        for func_idx in reverse_sequence:
            decrypted_char = REVERSE_FUNCTIONS[func_idx](decrypted_char, key)
        
        decrypted_message += chr(decrypted_char)
    
    return decrypted_message

# -------------------- PROGRAMA PRINCIPAL --------------------

def main():
    """
    Servidor de descifrado polimórfico.
    Recibe mensajes cifrados del cliente (encrypt.py) y los descifra.
    """
    Q = 32452843  # Número primo grande (clave fija en el servidor)
    key_table = None
    current_S = None
    current_P = None
    
    #configuracion de el servidor
    server_ip = '172.16.0.2'
    server_port = 65432

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((server_ip, server_port))
        s.listen()
        print("Esperando conexión...")
        conn, addr = s.accept()

        with conn:
            print(f"✅ Conexión establecida con {addr}")
            print("Esperando mensajes...")

            while True:
                try:
                    data = conn.recv(4096)
                    if not data:
                        print("-- Conexión cerrada por el cliente")
                        break
                    
                    message_data = pickle.loads(data)
                    message_type = message_data[0]
                    
                    # -------------------- FCM: Generar claves --------------------
                    if message_type == 'FCM':
                        _, P, S, num_keys = message_data
                        current_P = P
                        current_S = S
                        
                        key_table = generate_key_table(P, Q, S, num_keys)
                        print(f"-- Tabla de claves generada con FCM")
                        print(f"   P: {P}, S: {S}, Claves: {num_keys}")
                        
                        # Enviar confirmación y Q al cliente
                        conn.sendall(pickle.dumps(('FCM_ACK', Q)))
                    
                    # -------------------- RM: Recibir mensaje cifrado --------------------
                    elif message_type == 'RM':
                        if key_table is None:
                            print("Error: No hay tabla de claves")
                            continue
                            
                        _, encrypted_message, psn = message_data
                        decrypted_message = decrypt_message(encrypted_message, key_table, psn)
                        print(f"\nMENSAJE RECIBIDO:")
                        print(f"   PSN: {psn}")
                        print(f"   Texto: {decrypted_message}")
                        print(f"   Longitud: {len(decrypted_message)} caracteres")
                    
                    # -------------------- KUM: Actualizar claves --------------------
                    elif message_type == 'KUM':
                        _, new_S = message_data
                        current_S = new_S
                        key_table = generate_key_table(current_P, Q, current_S, len(key_table))
                        print(f"Claves actualizadas. Nueva S: {new_S}")
                    
                    # -------------------- LCM: Cerrar comunicación --------------------
                    elif message_type == 'LCM':
                        print("LCM recibido - Liberando comunicación")
                        key_table = None
                        current_S = None
                        current_P = None
                        break
                    
                except EOFError:
                    break
                except Exception as e:
                    print(f"Error procesando mensaje: {e}")

if __name__ == "__main__":
    main()
