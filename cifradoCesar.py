texto = input("Ingrese el texto que desea cifrar: ")
desplazamiento = int(input("Ingrese el desplazamiento: "))

texto_cifrado = ""

for caracter in texto:
    if caracter.isupper():
        nuevo_caracter = chr((ord(caracter) - ord('A') + desplazamiento) % 26 + ord('A'))
        texto_cifrado += nuevo_caracter

    elif caracter.islower():
        nuevo_caracter = chr((ord(caracter) - ord('a') + desplazamiento) % 26 + ord('a'))
        texto_cifrado += nuevo_caracter

    else:
        texto_cifrado += caracter

print("Texto cifrado:", texto_cifrado)