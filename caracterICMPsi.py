from scapy.all import IP, ICMP, Raw, send

# Pedir el texto cifrado obtenido del programa César
texto = input("Ingrese el texto cifrado: ")

# Pedir la IP de destino
destino = input("Ingrese la IP de destino: ")

# Patrón de datos utilizado por un ping normal de Linux:
# 56 bytes desde 0x00 hasta 0x37
patron_ping = bytes(range(0x00, 0x38))

# Recorrer el texto carácter por carácter
for numero, caracter in enumerate(texto, start=1):

    # Convertir el carácter actual a un byte
    caracter_byte = caracter.encode("utf-8")

    # Para caracteres ASCII normales, debe ocupar exactamente 1 byte
    if len(caracter_byte) != 1:
        print(f"Error: el carácter {repr(caracter)} no ocupa 1 byte.")
        continue

    # Crear una copia del patrón de ping
    datos = bytearray(patron_ping)

    # Colocar el carácter en el primer byte del Data
    datos[0] = caracter_byte[0]

    # Crear el paquete ICMP Echo Request
    paquete = (
        IP(dst=destino)
        / ICMP(type=8)
        / Raw(load=bytes(datos))
    )

    # Enviar el paquete
    send(paquete, verbose=False)

    # Mostrar información del paquete enviado
    print(f"Paquete {numero} enviado: {repr(caracter)}")