import socket
import pickle
import time
import random
from sympy import nextprime

# ==================== FUNCIONES DE GENERACIÓN DE CLAVES ====================

def scramble_function(x, y):
    """
    Función de mezcla inicial: Combina dos valores usando multiplicación y suma,
    luego aplica XOR para crear un valor inicial impredecible (P0).
    
    Esta operación proporciona no-linealidad y confusión en la generación de claves.
    
    Args:
        x (int): Primer valor de entrada (normalmente P)
        y (int): Segundo valor de entrada (normalmente S)
        
    Returns:
        int: Valor mezclado de 64 bits que servirá como base para generar claves
    """
    return (x * y) ^ (x + y)

def generation_function(P0, Q):
    """
    Genera una clave de 64 bits a partir de P0 y Q usando operaciones aritméticas
    y bitwise. Esta función es fundamental para la derivación de claves únicas.
    
    Args:
        P0 (int): Valor inicial generado por scramble_function
        Q (int): Número primo grande recibido del servidor
        
    Returns:
        int: Clave de 64 bits para cifrado/descifrado
    """
    return (P0 + Q) ^ (P0 * Q)

def mutation_function(S, Q):
    """
    Modifica el valor S utilizando Q para permitir el polimorfismo de claves.
    Con cada llamada, S muta creando una nueva base para la siguiente clave.
    
    Args:
        S (int): Semilla actual que será mutada
        Q (int): Número primo grande usado como parámetro de mutación
        
    Returns:
        int: Nueva semilla mutada para la siguiente iteración
    """
    return (S + Q) ^ (S * Q)

def generate_key_table(P, Q, S, num_keys):
    """
    Genera una tabla de claves de 64 bits iterativamente mutando la semilla S.
    Cada clave en la tabla es única debido al proceso de mutación secuencial.
    
    Args:
        P (int): Número primo grande generado por el cliente
        Q (int): Número primo grande recibido del servidor
        S (int): Semilla inicial para la generación de claves
        num_keys (int): Cantidad de claves a generar en la tabla
        
    Returns:
        list[int]: Lista de claves de 64 bits para cifrado/descifrado
    """
    key_table = []
    current_S = S
    
    # Generar num_keys claves iterativamente
    for i in range(num_keys):
        # Paso 1: Mezclar P con la semilla actual para crear P0
        P0 = scramble_function(P, current_S)
        
        # Paso 2: Generar clave usando P0 y Q
        key = generation_function(P0, Q)
        
        # Paso 3: Asegurar que la clave sea de 64 bits y agregar a la tabla
        key_table.append(key & 0xFFFFFFFFFFFFFFFF)
        
        # Paso 4: Mutar la semilla para la siguiente iteración
        current_S = mutation_function(current_S, Q)
        
        #print(f"Key[{i}]: {hex(key_table[-1])} (S: {current_S})")
    
    return key_table

# ==================== FUNCIONES REVERSIBLES DE CIFRADO ====================

def reversible_function_xor(data, key):
    """
    Función reversible XOR: Aplica operación XOR bit a bit entre el dato y la clave.
    
    Propiedades:
    - Simétrica: XOR es su propia inversa
    - Rápida computacionalmente
    - Proporciona confusión básica
    
    Args:
        data (int): Byte a cifrar (0-255)
        key (int): Clave de 64 bits (solo se usan los bits relevantes)
        
    Returns:
        int: Byte cifrado mediante XOR
    """
    return data ^ key

def reversible_function_rotate(data, key):
    """
    Función reversible de rotación: Rota los bits del byte a la izquierda.
    
    Propiedades:
    - Proporciona difusión de bits
    - La cantidad de rotación depende de la clave
    - Operación reversible con rotación inversa
    
    Args:
        data (int): Byte a rotar (0-255)
        key (int): Clave de 64 bits para determinar bits de rotación (0-7)
        
    Returns:
        int: Byte rotado
    """
    rotate_bits = key % 8  # Usar solo los últimos 3 bits (0-7)
    return ((data << rotate_bits) | (data >> (8 - rotate_bits))) & 0xFF

def reversible_function_substitute(data, key):
    """
    Función reversible de sustitución: Aplica una S-Box generada dinámicamente.
    
    Propiedades:
    - Proporciona confusión no-lineal
    - La S-Box es única para cada clave
    - Reversible mediante sustracción modular
    
    Args:
        data (int): Byte a sustituir (0-255)
        key (int): Clave de 64 bits para generar la S-Box
        
    Returns:
        int: Byte sustituido mediante la S-Box
    """
    # Generar S-Box dinámica: cada entrada i se mapea a (i + key) % 256
    sbox = [(i + key) % 256 for i in range(256)]
    return sbox[data]

# Diccionario para acceso rápido a las funciones reversibles
REVERSIBLE_FUNCTIONS = {
    0: reversible_function_xor,    # Función 0: XOR
    1: reversible_function_rotate, # Función 1: Rotación
    2: reversible_function_substitute  # Función 2: Sustitución
}

# ==================== FUNCIONES AUXILIARES ====================

def calculate_psn(message, previous_psn):
    """
    Calcula el Packet Sequence Number (PSN) para el mensaje actual.
    
    El PSN determina la secuencia de funciones a aplicar y se deriva del
    contenido del mensaje para aumentar la impredecibilidad.
    
    Args:
        message (str): Mensaje a cifrar
        previous_psn (int): PSN del mensaje anterior (None para el primero)
        
    Returns:
        int: Número de secuencia polimórfica (0-15)
    """
    if previous_psn is None:
        # Primer mensaje: usar primer carácter para derivar PSN
        return ord(message[0]) & 0x0F if message else 0
    else:
        # Mensajes subsiguientes: usar carácter en posición derivada del PSN anterior
        index = previous_psn % len(message)
        return ord(message[index]) & 0x0F

def get_function_sequence(psn, num_functions=3):
    """
    Genera la secuencia de funciones a aplicar basada en el PSN.
    
    La secuencia determina el orden de aplicación de las funciones reversibles
    y varía con cada mensaje gracias al PSN.
    
    Args:
        psn (int): Packet Sequence Number (0-15)
        num_functions (int): Número total de funciones disponibles (default: 3)
        
    Returns:
        list[int]: Secuencia de índices de funciones a aplicar
    """
    sequence = []
    temp_psn = psn
    
    # Generar secuencia de num_functions elementos
    for _ in range(num_functions):
        # Usar los últimos 2 bits del PSN temporal para seleccionar función
        sequence.append(temp_psn % num_functions)
        
        # Rotar bits del PSN temporal para variar la selección
        temp_psn = (temp_psn >> 2) | ((temp_psn & 0x03) << 2)
    
    return sequence

def encrypt_message(message, key_table, psn):
    """
    Cifra un mensaje aplicando una secuencia de funciones reversibles usando
    claves de la tabla de claves.
    
    Args:
        message (str): Mensaje plano a cifrar
        key_table (list[int]): Tabla de claves de 64 bits
        psn (int): Packet Sequence Number para este mensaje
        
    Returns:
        list[int]: Lista de bytes cifrados
    """
    encrypted_parts = []
    function_sequence = get_function_sequence(psn)
    
    #print(f"\n--- INICIANDO CIFRADO ---")
    #print(f"Mensaje: '{message}'")
    #print(f"PSN: {psn}")
    #print(f"Secuencia de funciones: {function_sequence}")
    
    for i, char in enumerate(message):
        # Seleccionar clave de la tabla de forma circular basada en PSN
        key_index = (i + psn) % len(key_table)
        key = key_table[key_index]
        encrypted_char = ord(char)  # Convertir carácter a valor ASCII
        
        #print(f"\nCarácter {i}: '{char}' (ASCII: {encrypted_char})")
        #print(f"Clave seleccionada: Key[{key_index}] = {hex(key)}")
        
        # Aplicar cada función en la secuencia determinada por el PSN
        for func_idx in function_sequence:
            old_val = encrypted_char
            encrypted_char = REVERSIBLE_FUNCTIONS[func_idx](encrypted_char, key)
            #print(f"  Función {func_idx}: {old_val} → {encrypted_char}")
        
        encrypted_parts.append(encrypted_char)
        #print(f"  Resultado final: {encrypted_char}")
    
    #print(f"--- CIFRADO COMPLETADO ---")
    return encrypted_parts

# ==================== FUNCIONES DE GENERACIÓN DE PARÁMETROS ====================

def generar_primo_P():
    """
    Genera un número primo grande de 8 dígitos para el parámetro P.
    
    Returns:
        int: Número primo de aproximadamente 8 dígitos
    """
    numero = random.randint(10000000, 99999999)
    return nextprime(numero)

def generar_semilla():
    """
    Genera una semilla inicial de 9 dígitos para el parámetro S.
    
    Returns:
        int: Semilla numérica de 9 dígitos
    """
    return random.randint(100000000, 999999999)

# ==================== MENU INTERACTIVO ====================

def mostrar_menu():
    """
    Muestra el menú principal de opciones para el usuario.
    
    Returns:
        str: Opción seleccionada por el usuario
    """
    print("\n" + "="*50)
    print("        CIFRADO POLIMÓRFICO - CLIENTE")
    print("="*50)
    print("1.  Enviar Mensaje Regular (RM)")
    print("2.  Actualizar Claves (KUM)")
    print("3.  Finalizar Conexión (LCM)")
    print("4.  Mostrar Estado Actual")
    print("5.  Salir")
    print("="*50)
    return input("Selecciona una opción (1-5): ").strip()

# ==================== PROGRAMA PRINCIPAL ====================

def main():
    """
    Función principal del cliente de cifrado polimórfico.
    
    Gestiona la conexión con el servidor, generación de claves,
    y proporciona interfaz para enviar mensajes cifrados.
    """
    # Inicializar parámetros criptográficos
    P = generar_primo_P()  # Número primo grande del cliente
    S = generar_semilla()  # Semilla inicial
    num_keys = 15          # Número de claves a generar
    previous_psn = None    # PSN del mensaje anterior
    key_table = None       # Tabla de claves (se genera después de FCM)
    Q = None               # Número primo del servidor (se recibe después de FCM)
    
    # Configuración de conexión
    server_ip = 'localhost'
    server_port = 65432

    try:
        # Establecer conexión TCP con el servidor
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((server_ip, server_port))
            print("✅ Conectado al servidor")
            
            # Paso 1: Enviar FCM (First Contact Message) - Inicializar comunicación
            print("Enviando FCM (First Contact Message)...")
            fcm_data = pickle.dumps(('FCM', P, S, num_keys))
            s.sendall(fcm_data)
            
            # Paso 2: Recibir Q del servidor (confirmación FCM_ACK)
            response = pickle.loads(s.recv(1024))
            if response[0] == 'FCM_ACK':
                Q = response[1]
                # Generar tabla de claves con todos los parámetros
                key_table = generate_key_table(P, Q, S, num_keys)
                print(f"Tabla de claves generada ({len(key_table)} claves)")
                print(f"Q recibido del servidor: {Q}")
            
            # Bucle principal del menú interactivo
            while True:
                opcion = mostrar_menu()
                
                if opcion == '1':  # Enviar mensaje regular (RM)
                    mensaje = input("Ingresa el mensaje a cifrar: ").strip()
                    if not mensaje:
                        print("Error: El mensaje no puede estar vacío")
                        continue
                    
                    # Calcular PSN y cifrar mensaje
                    psn = calculate_psn(mensaje, previous_psn)
                    encrypted_message = encrypt_message(mensaje, key_table, psn)
                    
                    # Enviar mensaje cifrado al servidor
                    rm_data = pickle.dumps(('RM', encrypted_message, psn))
                    s.sendall(rm_data)
                    print(f"Mensaje enviado con PSN: {psn}")
                    previous_psn = psn  # Actualizar PSN para próximo mensaje
                    time.sleep(1)  # Pequeña pausa para estabilidad
                
                elif opcion == '2':  # Actualizar claves (KUM - Key Update Message)
                    nueva_S = S + 1  # Incrementar semilla para nueva generación
                    kum_data = pickle.dumps(('KUM', nueva_S))
                    s.sendall(kum_data)
                    
                    # Regenerar tabla de claves con nueva semilla
                    key_table = generate_key_table(P, Q, nueva_S, num_keys)
                    S = nueva_S  # Actualizar semilla actual
                    print(f"Claves actualizadas. Nueva S: {S}")
                    time.sleep(1)
                
                elif opcion == '3':  # Finalizar conexión (LCM - Last Contact Message)
                    lcm_data = pickle.dumps(('LCM',))
                    s.sendall(lcm_data)
                    print("Conexión finalizada con el servidor")
                    break
                
                elif opcion == '4':  # Mostrar estado actual
                    print("\nESTADO ACTUAL DEL CLIENTE:")
                    print(f"   P (Primo cliente): {P}")
                    print(f"   Q (Primo servidor): {Q}")
                    print(f"   S (Semilla actual): {S}")
                    print(f"   Número de claves: {len(key_table) if key_table else 0}")
                    print(f"   Último PSN usado: {previous_psn}")
                    
                    if key_table:
                        print("\nTABLA DE CLAVES ACTUAL:")
                        for i, key in enumerate(key_table):
                            print(f"   Key[{i}]: {hex(key)}")
                    
                    input("\nPresiona Enter para continuar...")
                
                elif opcion == '5':  # Salir del programa
                    print("Saliendo del cliente...")
                    break
                
                else:
                    print("Opción no válida. Intenta de nuevo.")
    
    except ConnectionRefusedError:
        print("No se pudo conectar al servidor. Asegúrate de que decrypt.py esté ejecutándose.")
    except Exception as e:
        print(f"Error inesperado: {e}")

if __name__ == "__main__":
    main()