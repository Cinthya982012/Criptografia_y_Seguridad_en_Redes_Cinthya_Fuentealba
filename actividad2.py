from scapy.all import IP, ICMP, Raw, send

# --------------------------------------------------
# 1. Solicitar el texto cifrado
# --------------------------------------------------

texto = input("Ingrese el texto cifrado: ")

# Solicitar IP de destino
destino = input("Ingrese la IP de destino: ")

# --------------------------------------------------
# 2. Configuración de los paquetes
# --------------------------------------------------

# Identifier ICMP constante durante la transmisión
icmp_id = 1

# ID inicial del encabezado IP
ip_id = 1

# Patrón de datos del ping
patron_ping = bytes(range(0x00, 0x38))

# --------------------------------------------------
# 3. Enviar un carácter por paquete
# --------------------------------------------------

for numero, caracter in enumerate(texto, start=1):

    # Convertir el carácter a bytes
    caracter_byte = caracter.encode("utf-8")

    # Verificar que ocupe un byte
    if len(caracter_byte) != 1:
        print(
            f"Error: el carácter {repr(caracter)} "
            "no ocupa exactamente 1 byte."
        )
        continue

    # Crear una copia del payload
    datos = bytearray(patron_ping)

    # --------------------------------------------------
    # IMPORTANTE:
    # El carácter se mantiene en el primer byte
    # porque la Actividad 3 recupera datos[0]
    # --------------------------------------------------

    datos[0] = caracter_byte[0]

    # --------------------------------------------------
    # Crear paquete
    # --------------------------------------------------

    paquete = (
        IP(
            dst=destino,
            id=ip_id
        )
        /
        ICMP(
            type=8,
            code=0,
            id=icmp_id,
            seq=numero
        )
        /
        Raw(
            load=bytes(datos)
        )
    )

    # Enviar paquete
    send(paquete, verbose=False)

    print(
        f"Paquete {numero} enviado: "
        f"{repr(caracter)} | "
        f"IP ID={ip_id} | "
        f"ICMP ID={icmp_id} | "
        f"SEQ={numero}"
    )

    # Aumentar ID IP
    ip_id += 1