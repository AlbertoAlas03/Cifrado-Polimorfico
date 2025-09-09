# 🚀 Cifrado Polimórfico en Python

Este proyecto implementa un sistema de **cifrado polimórfico** cliente-servidor utilizando **Python** y **sockets**.  
El objetivo es enviar mensajes cifrados desde un cliente hacia un servidor, donde son descifrados en tiempo real.

---

## 📁 Archivos del proyecto

| Archivo        | Descripción |
|----------------|-------------|
| `encrypt.py`   | Cliente que cifra mensajes y los envía al servidor. |
| `decrypt.py`   | Servidor que recibe mensajes cifrados y los descifra. |

---

## 🧑‍💻 Tecnologías utilizadas

- **Python 3**
- **Sockets TCP/IP**
- **Pickle** para serialización de datos
- Algoritmos de cifrado polimórfico (XOR, rotación de bits, sustitución S-Box)

---

## ¿Qué es el cifrado polimórfico?

El cifrado polimórfico es un tipo de cifrado que **modifica dinámicamente el algoritmo o las claves utilizadas** en cada mensaje, dificultando su análisis y criptoanálisis.

En este proyecto:
- Cada mensaje se cifra usando una **secuencia aleatoria de funciones reversibles**.
- Se utiliza un valor **PSN (Polymorphic Sequence Number)** para determinar el orden de cifrado.
- El servidor y el cliente comparten parámetros (`P`, `Q`, `S`) para generar la misma **tabla de claves**.
- Cada vez que el PSN cambia, la secuencia de cifrado también cambia.

---

## ➡️ Flujo de comunicación

1. **Inicio de conexión**  
   - El cliente envía un **FCM (First Contact Message)** con `P`, `S` y número de claves.
   - El servidor responde con `Q` y genera la tabla de claves.

2. **Envío de mensaje regular (RM)**  
   - El cliente cifra el mensaje con su tabla de claves y PSN.
   - El servidor descifra el mensaje usando la misma secuencia de funciones.

3. **Actualización de claves (KUM)**  
   - El cliente puede solicitar al servidor que regenere la tabla de claves con un nuevo valor `S`.

4. **Liberación de conexión (LCM)**  
   - El cliente informa que finalizará la comunicación y el servidor limpia la sesión.

---

### 🛠️ Funciones principales

1. `scramble_function(x, y)`

**Proposito:** Mezcla dos valores usando operaciones aritméticas y bitwise para aumentar la aleatoriedad.

**operación:**
```bash
return (x * y) ^ (x + y)
```

2. `generation_function(P0, Q)`

**Proposito:** Genera una clave de 64 bits a partir de `P0` y `Q`.

**operación:**
```bash
return (P0 + Q) ^ (P0 * Q) & 0xFFFFFFFFFFFFFFFF
```

3. `mutation_function(S, Q)`

**Proposito:** Modifica el valor de `S` para generar nuevas claves en cada iteración.

**operación:**
```bash
return (S + Q) ^ (S * Q)
```

4. `generate_key_table(P, Q, S, num_keys)`

**Proposito:** Genera una tabla de claves de 64 bits usando los parámetros iniciales.

**Flujo:**
- Calcula `P0 = scramble_function(P, S)`
- Genera clave: `key = generation_function(P0, Q)`
- Actualiza `S` con `mutation_function(S, Q)`
- Repite `num_keys` veces

5. `encrypt_message(message, key_table, psn)`

**Proposito:** Cifra un mensaje aplicando una secuencia de funciones reversibles.

**Pasos:**
1. Calcula la secuencia de funciones con `get_function_sequence(psn)`
2. Para cada carácter:
- Selecciona una clave de la tabla según `(i + psn) % len(key_table)`
- Aplica las funciones en el orden de la secuencia
3. Devuelve lista de bytes cifrados

6. `calculate_psn(message, previous_psn)`

**Proposito:** Calcula el Packet Sequence Number (PSN) para el mensaje.

**Reglas:**
- Si es el primer mensaje: `ord(message[0]) & 0x0F`
- Para mensajes siguientes: `ord(message[previous_psn % len(message)]) & 0x0F`

7. `get_function_sequence(psn, num_functions=3)`

**Proposito:** Genera una secuencia de índices de funciones basada en el PSN.

**Ejemplo:**

Si `psn = 5` → `[5 % 3, (5 >> 2) | (...), ...]` → `[2, 1, 0]`

### 🔧 Funciones reversibles

1. `reversible_function_xor(data, key)`
```bash
return (S + Q) ^ (S * Q)
```

2. `reversible_function_rotate(data, key)`

Rota a la izquierda `key % 8` bits.

3. `reversible_function_substitute(data, key)`

Aplica una S-Box generada dinámicamente:
```bash
sbox = [(i + key) % 256 for i in range(256)]
return sbox[data]
```

### 🔓 Funciones de descifrado

`decrypt_message(encrypted_parts, key_table, psn)`

**Proposito:** Descifra una lista de bytes aplicando las funciones inversas en orden reverso.

**Pasos:**

1. Obtiene la secuencia de funciones con `get_function_sequence(psn)`
2. Invierte la secuencia: `reverse_sequence = list(reversed(sequence))`
3. Para cada byte cifrado:
- Aplica las funciones inversas en orden inverso
- Convierte a carácter y concatena

### 📨 Tipos de mensajes procesados

1. `FCM`
- Recibe: `('FCM', P, S, num_keys)`
- Genera tabla de claves
- Envía `('FCM_ACK', Q)`

2. `RM`
- Recibe: `('RM', encrypted_message, psn)`
- Descifra y muestra el mensaje

3. `KUM`
- Recibe: `('KUM', new_S)`
- Regenera la tabla de claves con la nueva `S`

4. `LCM`
- Recibe: `('LCM',)`
- Limpia estado y cierra conexión

## Ejecución

### Iniciar el servidor (decrypt.py)
```bash
python decrypt.py
```

#### Iniciar el cliente (encrypt.py)
```bash
python encrypt.py
```
---

### ✅ Ahora ya puedes interactuar desde el cliente con el menú principal con las diferentes opciones disponibles.