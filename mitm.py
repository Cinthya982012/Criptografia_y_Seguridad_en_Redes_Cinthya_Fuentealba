from scapy.all import sniff, ICMP

# --------------------------------------------------
# 1. Solicitar cantidad de caracteres
# --------------------------------------------------

cantidad = int(input("Ingrese la cantidad de caracteres del mensaje: "))

mensaje = ""

print("\nEsperando paquetes ICMP Echo Request...")
print("Ejecute ahora el programa emisor del paso 2.\n")


# --------------------------------------------------
# 2. Función para procesar cada paquete
# --------------------------------------------------

def recibir_paquete(paquete):

    global mensaje

    if paquete.haslayer(ICMP) and paquete[ICMP].type == 8:

        datos = bytes(paquete[ICMP].payload)

        if len(datos) > 0:

            caracter = chr(datos[0])

            mensaje += caracter

            print(
                f"Paquete {len(mensaje)} recibido: "
                f"{repr(caracter)}"
            )


# --------------------------------------------------
# 3. Capturar paquetes
# --------------------------------------------------

sniff(
    filter="icmp",
    prn=recibir_paquete,
    stop_filter=lambda paquete: len(mensaje) >= cantidad
)


# --------------------------------------------------
# 4. Mostrar mensaje cifrado recuperado
# --------------------------------------------------

print("\n========================================")
print("MENSAJE CIFRADO RECUPERADO")
print("========================================")

print(repr(mensaje))


# --------------------------------------------------
# 5. Descifrado César
# --------------------------------------------------

def descifrar_cesar(texto, desplazamiento):

    resultado = ""

    for caracter in texto:

        if 'A' <= caracter <= 'Z':

            posicion = (
                ord(caracter) - ord('A') - desplazamiento
            ) % 26

            resultado += chr(
                posicion + ord('A')
            )

        elif 'a' <= caracter <= 'z':

            posicion = (
                ord(caracter) - ord('a') - desplazamiento
            ) % 26

            resultado += chr(
                posicion + ord('a')
            )

        else:

            resultado += caracter

    return resultado


# --------------------------------------------------
# 6. Sistema de puntuación para español
# --------------------------------------------------

palabras_comunes = [
    " EL ",
    " LA ",
    " LOS ",
    " LAS ",
    " DE ",
    " DEL ",
    " QUE ",
    " Y ",
    " EN ",
    " UN ",
    " UNA ",
    " ES ",
    " POR ",
    " PARA ",
    " CON ",
    " SE ",
    " AL ",
    " COMO ",
    " HOLA ",
    " MENSAJE "
]


def puntuar(texto):

    texto_busqueda = " " + texto.upper() + " "

    puntuacion = 0

    for palabra in palabras_comunes:
        puntuacion += texto_busqueda.count(palabra) * 10

    frecuencias = {
        'E': 1.0,
        'A': 0.9,
        'O': 0.8,
        'S': 0.7,
        'N': 0.7,
        'R': 0.6,
        'I': 0.6,
        'L': 0.5,
        'D': 0.5,
        'T': 0.5
    }

    for caracter in texto.upper():

        if caracter in frecuencias:
            puntuacion += frecuencias[caracter]

    return puntuacion


# --------------------------------------------------
# 7. Generar las 26 posibilidades
# --------------------------------------------------

posibilidades = []

for desplazamiento in range(26):

    texto_claro = descifrar_cesar(
        mensaje,
        desplazamiento
    )

    puntuacion = puntuar(texto_claro)

    posibilidades.append(
        (
            puntuacion,
            desplazamiento,
            texto_claro
        )
    )


# --------------------------------------------------
# 8. Ordenar por probabilidad
# --------------------------------------------------

posibilidades.sort(
    reverse=True,
    key=lambda elemento: elemento[0]
)


# --------------------------------------------------
# 9. Mostrar resultados
# --------------------------------------------------

print("\n========================================")
print("TODAS LAS COMBINACIONES")
print("========================================\n")

for numero, (puntuacion, desplazamiento, texto) in enumerate(
    posibilidades,
    start=1
):

    if numero == 1:

        print(
            f"\033[92m"
            f"Desplazamiento {desplazamiento:2d}: "
            f"{texto} "
            f"<-- MÁS PROBABLE"
            f"\033[0m"
        )

    else:

        print(
            f"Desplazamiento {desplazamiento:2d}: "
            f"{texto}"
        )