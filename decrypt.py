import socket
import pickle
import random
from sympy import nextprime

# ==================== FUNCIONES DE GENERACIÓN DE CLAVES ====================

def scramble_function(x, y):
    """
    Función de mezcla idéntica a la del cliente para garantizar compatibilidad.
    """
    return (x * y) ^ (x + y)

def generation_function(P0, Q):
    """
    Función de generación de claves idéntica a la del cliente.
    """
    return (P0 + Q) ^ (P0 * Q)

def mutation_function(S, Q):
    """
    Función de mutación idéntica a la del cliente.
    """
    return (S + Q) ^ (S * Q)

def generate_key_table(P, Q, S, num_keys):
    """
    Genera la misma tabla de claves que el cliente usando los mismos parámetros.
    
    Esta función debe ser idéntica a la del cliente para garantizar que
    ambas partes generen las mismas claves para cifrado/descifrado.
    """
    key_table = []
    current_S = S
    
    for _ in range(num_keys):
        P0 = scramble_function(P, current_S)
        key = generation_function(P0, Q)
        key_table.append(key & 0xFFFFFFFFFFFFFFFF)
        current_S = mutation_function(current_S, Q)
    
    return key_table

# ==================== FUNCIONES REVERSIBLES Y SUS INVERSAS ====================

def reversible_function_xor(data, key):
    """Función XOR (es su propia inversa)."""
    return data ^ key

def reversible_function_rotate(data, key):
    """Función de rotación a la izquierda."""
    rotate_bits = key % 8
    return ((data << rotate_bits) | (data >> (8 - rotate_bits))) & 0xFF

def reversible_function_substitute(data, key):
    """Función de sustitución con S-Box dinámica."""
    sbox = [(i + key) % 256 for i in range(256)]
    return sbox[data]

# Diccionario de funciones reversibles (mismo que el cliente)
REVERSIBLE_FUNCTIONS = {
    0: reversible_function_xor,
    1: reversible_function_rotate,
    2: reversible_function_substitute
}

# Diccionario de funciones inversas para descifrado
REVERSE_FUNCTIONS = {
    0: reversible_function_xor,  # XOR es su propia inversa
    1: lambda data, key: ((data >> (key % 8)) | (data << (8 - (key % 8)))) & 0xFF,  # Rotación derecha
    2: lambda data, key: (data - key) % 256  # Sustitución inversa
}

# ==================== FUNCIONES AUXILIARES ====================

def get_function_sequence(psn, num_functions=3):
    """
    Genera la misma secuencia de funciones que el cliente basada en el PSN.
    
    Esta función debe ser idéntica a la del cliente para garantizar que
    se use el mismo orden de funciones para descifrar.
    """
    sequence = []
    temp_psn = psn
    
    for _ in range(num_functions):
        sequence.append(temp_psn % num_functions)
        temp_psn = (temp_psn >> 2) | ((temp_psn & 0x03) << 2)
    
    return sequence

def decrypt_message(encrypted_parts, key_table, psn):
    """
    Descifra un mensaje aplicando las funciones inversas en orden reverso.
    
    Args:
        encrypted_parts (list[int]): Lista de bytes cifrados
        key_table (list[int]): Tabla de claves (debe ser idéntica a la del cliente)
        psn (int): Packet Sequence Number recibido del cliente
        
    Returns:
        str: Mensaje descifrado
    """
    decrypted_message = ""
    function_sequence = get_function_sequence(psn)
    reverse_sequence = list(reversed(function_sequence))  # Orden inverso para descifrado
    
    #print(f"\n--- INICIANDO DESCIFRADO ---")
    #print(f"PSN recibido: {psn}")
    #print(f"Secuencia de funciones: {function_sequence}")
    #print(f"Secuencia inversa: {reverse_sequence}")
    
    for i, encrypted_char in enumerate(encrypted_parts):
        # Seleccionar la misma clave que usó el cliente
        key_index = (i + psn) % len(key_table)
        key = key_table[key_index]
        decrypted_char = encrypted_char
        
        #print(f"\nByte cifrado {i}: {encrypted_char}")
        #print(f"Clave seleccionada: Key[{key_index}] = {hex(key)}")
        
        # Aplicar funciones inversas en orden reverso
        for func_idx in reverse_sequence:
            old_val = decrypted_char
            decrypted_char = REVERSE_FUNCTIONS[func_idx](decrypted_char, key)
            #print(f"  Función inversa {func_idx}: {old_val} → {decrypted_char}")
        
        decrypted_message += chr(decrypted_char)
        #print(f"  Carácter descifrado: '{chr(decrypted_char)}'")
    
    #print(f"--- DESCIFRADO COMPLETADO ---")
    return decrypted_message

# ==================== FUNCIONES DE GENERACIÓN DE PARÁMETROS ====================

def generar_primo_Q():
    """
    Genera un número primo grande de 8 dígitos para el parámetro Q del servidor.
    
    Returns:
        int: Número primo de aproximadamente 8 dígitos
    """
    numero = random.randint(10000000, 99999999)
    return nextprime(numero)

# ==================== PROGRAMA PRINCIPAL ====================

def main():
    """
    Función principal del servidor de descifrado polimórfico.
    
    Escucha conexiones, procesa mensajes del cliente y descifra los mensajes
    usando las mismas claves y algoritmos que el cliente.
    """
    # Parámetros del servidor
    Q = generar_primo_Q()  # Número primo grande del servidor (fijo)
    key_table = None       # Tabla de claves (se genera con FCM)
    current_S = None       # Semilla actual (se recibe del cliente)
    current_P = None       # Primo del cliente (se recibe con FCM)
    
    # Configuración del servidor
    server_ip = 'localhost'
    server_port = 65432

    # Crear socket TCP y escuchar conexiones
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((server_ip, server_port))
        s.listen()
        print("Esperando conexión del cliente...")
        
        # Aceptar conexión entrante
        conn, addr = s.accept()
        print(f"✅ Conexión establecida con {addr}")

        with conn:
            print("Esperando mensajes del cliente...")

            while True:
                try:
                    # Recibir datos del cliente
                    data = conn.recv(4096)
                    if not data:
                        print("-- Conexión cerrada por el cliente")
                        break
                    
                    # Deserializar datos recibidos
                    message_data = pickle.loads(data)
                    message_type = message_data[0]
                    
                    # -------------------- FCM: FIRST CONTACT MESSAGE --------------------
                    if message_type == 'FCM':
                        print("\nFCM recibido - Inicializando comunicación")
                        _, P, S, num_keys = message_data
                        current_P = P
                        current_S = S
                        
                        # Generar tabla de claves con los parámetros del cliente
                        key_table = generate_key_table(P, Q, S, num_keys)
                        print(f"Tabla de claves generada")
                        print(f"   P (cliente): {P}")
                        print(f"   S (semilla): {S}")
                        print(f"   Claves generadas: {num_keys}")
                        
                        # Mostrar tabla de claves generada
                        print("\nTABLA DE CLAVES GENERADA:")
                        for i, key in enumerate(key_table):
                            print(f"   Key[{i}]: {hex(key)}")
                        print("-------------------------------")
                        
                        # Enviar confirmación y parámetro Q al cliente
                        conn.sendall(pickle.dumps(('FCM_ACK', Q)))
                        print(f"FCM_ACK enviado con Q: {Q}")
                    
                    # -------------------- RM: REGULAR MESSAGE --------------------
                    elif message_type == 'RM':
                        if key_table is None:
                            print("Error: No hay tabla de claves. FCM no recibido.")
                            continue
                            
                        print("\nRM recibido - Descifrando mensaje...")
                        _, encrypted_message, psn = message_data
                        
                        # Descifrar mensaje usando la misma tabla de claves
                        decrypted_message = decrypt_message(encrypted_message, key_table, psn)
                        
                        print(f"MENSAJE DESCIFRADO:")
                        print(f"   PSN: {psn}")
                        print(f"   Texto: '{decrypted_message}'")
                        print(f"   Longitud: {len(decrypted_message)} caracteres")
                    
                    # -------------------- KUM: KEY UPDATE MESSAGE --------------------
                    elif message_type == 'KUM':
                        print("\nKUM recibido - Actualizando claves...")
                        _, new_S = message_data
                        current_S = new_S
                        
                        # Regenerar tabla de claves con la nueva semilla
                        key_table = generate_key_table(current_P, Q, current_S, len(key_table))
                        print(f"Claves actualizadas. Nueva S: {new_S}")
                    
                    # -------------------- LCM: LAST CONTACT MESSAGE --------------------
                    elif message_type == 'LCM':
                        print("\nLCM recibido - Finalizando comunicación")
                        # Limpiar estado para nueva conexión
                        key_table = None
                        current_S = None
                        current_P = None
                        print("Estado limpiado. Listo para nueva conexión.")
                        break
                    
                except EOFError:
                    print("Error de deserialización: datos corruptos")
                    break
                except Exception as e:
                    print(f"Error procesando mensaje: {e}")
                    break

if __name__ == "__main__":
    main()