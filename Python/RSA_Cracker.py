# RSA Cracker

from math import isqrt

n = int(input("\n[+] Ingresa el módulo (n) -> "))
e = int(input("\n[+] Ingresa el exponente  público (e) -> "))
C = int(input("\n[+] Ingresa el valor del mensaje cifrado (C) -> "))


def crack_RSA(n, e, C):
    #Factorizar n
    p = None

    for i in range(2, isqrt(n) + 1):
        if n % i == 0:
            p = i
            break
    
    if p is None:
        return "\n[!] No se encuentran valores en este rango."
    
    q = (n // p)
    print(f"[+] Se ha encontrado p y q:\n\t[+] p={p}\n\t[+] q={q}")

    #Calcular el totiente usando la formula de Euler: phi(n) = (p-1)*(q-1)
    phi = (p - 1) * (q - 1)
    print(f"\n[+] Totiente={phi}")

    #Calcular la clave privada (d)
    try:
        d = pow(e, -1, phi)
        print(f"\n[+] Clave privada (d): {d}")
    except ValueError:
        return "\n[!] No existe inverso modular (e y phi no son coprimos)."
    
    #Descifrar el mensaje: M = C^d mod n
    M = pow(C, d, n)
    print(f"\n[+] Mensaje original (M): {M}")

    try:
        mensaje_ascii = chr(M)
        print(f"\n[+] Mensaje en ascii: {mensaje_ascii}")
    except Exception:
        print(f"\n[!] No se ha podido obtener un valor en ascii de: {M}\n")

    return p, q, d, M

if (n.bit_length()) < 2048:
    crack_RSA(n, e, C)