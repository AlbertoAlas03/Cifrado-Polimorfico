# Cifrado Polimórfico en Python

Este proyecto implementa un sistema de **cifrado polimórfico** cliente-servidor utilizando **Python** y **sockets**.  
El objetivo es enviar mensajes cifrados desde un cliente hacia un servidor, donde son descifrados en tiempo real.

---

## Archivos del proyecto

| Archivo        | Descripción |
|----------------|-------------|
| `encrypt.py`   | Cliente que cifra mensajes y los envía al servidor. |
| `decrypt.py`   | Servidor que recibe mensajes cifrados y los descifra. |

---

## Tecnologías utilizadas

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

## Flujo de comunicación

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