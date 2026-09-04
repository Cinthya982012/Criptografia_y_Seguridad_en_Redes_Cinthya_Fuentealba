from scapy.all import sniff, ICMP, IP

VERDE = "\033[92m"
RESET = "\033[0m"

mensaje_cifrado = []

# Pedir cantidad de caracteres esperados
cantidad_esperada = int(
    input("Ingrese la cantidad de caracteres del mensaje cifrado: ")
)


def descifrar_cesar(texto, desplazamiento):

    resultado = ""

    for caracter in texto:

        if 'A' <= caracter <= 'Z':
            resultado += chr(
                (ord(caracter) - ord('A') - desplazamiento) % 26
                + ord('A')
            )

        elif 'a' <= caracter <= 'z':
            resultado += chr(
                (ord(caracter) - ord('a') - desplazamiento) % 26
                + ord('a')
            )

        else:
            resultado += caracter

    return resultado


def procesar_paquete(paquete):

    if IP in paquete and ICMP in paquete:

        # Solo ICMP Echo Request
        if paquete[ICMP].type == 8:

            datos = bytes(paquete[ICMP].payload)

            if len(datos) > 0:

                # Obtener primer byte del payload
                caracter = chr(datos[0])

                mensaje_cifrado.append(caracter)

                print(f"Carácter recibido: {caracter}")

                print(
                    f"Mensaje cifrado actual: "
                    f"{VERDE}{''.join(mensaje_cifrado)}{RESET}"
                )

                # Si recibió todos los caracteres, detener captura
                if len(mensaje_cifrado) >= cantidad_esperada:
                    return True


print("\n========================================")
print("       ACTIVIDAD 3 - RECEPTOR ICMP")
print("========================================")

print("\nEsperando paquetes ICMP...\n")

sniff(
    filter="icmp",
    prn=procesar_paquete,
    store=False,
    stop_filter=lambda paquete: len(mensaje_cifrado) >= cantidad_esperada
)


# ========================================
# MENSAJE COMPLETO
# ========================================

texto = "".join(mensaje_cifrado)

print("\n========================================")
print("      MENSAJE CIFRADO COMPLETO")
print("========================================")

print(f"\n{VERDE}{texto}{RESET}")


# ========================================
# 26 POSIBILIDADES
# ========================================

print("\n========================================")
print("   26 POSIBILIDADES CIFRADO CÉSAR")
print("========================================\n")

for desplazamiento in range(26):

    resultado = descifrar_cesar(
        texto,
        desplazamiento
    )

    if desplazamiento == 7:
        print(
            f"{VERDE}"
            f"Desplazamiento {desplazamiento}: {resultado}"
            f"{RESET}"
        )
    else:
        print(
            f"Desplazamiento {desplazamiento}: {resultado}"
        )