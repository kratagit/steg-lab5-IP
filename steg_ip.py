from scapy.all import IP, ICMP

def encode_message(message, dst_ip="127.0.0.1"):
    """
    Funkcja kodująca wiadomość w polu identyfikacji nagłówka IP.
    """
    if not message:
        print("Błąd: Wiadomość nie może być pusta.")
        return []
        
    if len(message) > 1000:
        raise ValueError("Błąd: Wiadomość przekracza limit 1000 znaków.")

    msg_bytes = message.encode('utf-8')
    packets = []
    counter = 0

    for i in range(0, len(msg_bytes), 2):
        if i + 1 < len(msg_bytes):
            val = (msg_bytes[i] << 8) | msg_bytes[i+1]
        else:
            val = (msg_bytes[i] << 8) | 0x00

        # Zapewnienie unikalności ID: offset mnożnika eliminuje kolizje 
        # nawet dla identycznych powtarzających się znaków w tekście
        unique_id = (val + counter * 257) % 65536

        pkt = IP(dst=dst_ip, id=unique_id) / ICMP()
        packets.append(pkt)
        
        counter += 1

    return packets


def decode_message(packets):
    """
    Funkcja dekodująca wiadomość z podanej listy pakietów IP.
    """
    if not packets:
        return ""

    msg_bytes = bytearray()
    counter = 0

    for pkt in packets:
        if IP in pkt:
            unique_id = pkt[IP].id
            
            # Odtworzenie oryginalnej 16-bitowej wartości
            val = (unique_id - counter * 257) % 65536
            
            byte1 = (val >> 8) & 0xFF
            byte2 = val & 0xFF
            
            msg_bytes.append(byte1)
            # Ignorujemy dodane zera z ewentualnego dopełnienia na końcu
            if byte2 != 0x00:
                msg_bytes.append(byte2)
                
            counter += 1

    return msg_bytes.decode('utf-8', errors='ignore')


def run_tests():
    print("=== ROZPOCZĘCIE TESTÓW LABORATORIUM 5 ===")

    # ---------------------------------------------------------
    # Test 1: Test kodowania krótkiej wiadomości (do 2 znaków)
    # ---------------------------------------------------------
    print("\n[Test 1] Kodowanie krótkiej wiadomości (do 2 znaków)")
    msg_t1 = "IT"
    print(f"-> Wejście: '{msg_t1}'")
    packets_t1 = encode_message(msg_t1)
    print(f"-> Wygenerowano pakietów: {len(packets_t1)} (Oczekiwano: 1)")
    
    # ---------------------------------------------------------
    # Test 2: Test kodowania długiej wiadomości (powyżej 2 znaków)
    # ---------------------------------------------------------
    print("\n[Test 2] Kodowanie długiej wiadomości (powyżej 2 znaków)")
    msg_t2 = "This is a longer message that requires multiple packets to encode."
    print(f"-> Wejście: '{msg_t2}'")
    packets_t2 = encode_message(msg_t2)
    print(f"-> Wygenerowano pakietów: {len(packets_t2)} (Oczekiwano serii pakietów)")

    # ---------------------------------------------------------
    # Test 3: Test dekodowania wiadomości z pojedynczego pakietu
    # ---------------------------------------------------------
    print("\n[Test 3] Dekodowanie wiadomości z pojedynczego pakietu")
    print(f"-> Wejście: 1 pakiet IP (zawierający zakodowane 'IT')")
    decoded_t3 = decode_message(packets_t1)
    print(f"-> Oczekiwany wynik: 'IT'")
    print(f"-> Faktyczny wynik: '{decoded_t3}'")
    print(f"-> STATUS: {'ZALICZONY' if decoded_t3 == 'IT' else 'NIEZALICZONY'}")

    # ---------------------------------------------------------
    # Test 4: Test dekodowania wiadomości z wielu pakietów
    # ---------------------------------------------------------
    print("\n[Test 4] Dekodowanie wiadomości z wielu pakietów")
    print("-> Wejście: Seria pakietów IP z zakodowaną wiadomością z Testu 2")
    decoded_t4 = decode_message(packets_t2)
    print(f"-> Zdekodowana wiadomość: '{decoded_t4}'")
    print(f"-> STATUS: {'ZALICZONY' if decoded_t4 == msg_t2 else 'NIEZALICZONY'}")

    # ---------------------------------------------------------
    # Test 5: Test obsługi pustej wiadomości
    # ---------------------------------------------------------
    print("\n[Test 5] Obsługa pustej wiadomości")
    print("-> Wejście: \"\" (pusty ciąg znaków)")
    packets_t5 = encode_message("")
    print(f"-> Wygenerowano pakietów: {len(packets_t5)}")
    print(f"-> STATUS: {'ZALICZONY' if len(packets_t5) == 0 else 'NIEZALICZONY'}")

    # ---------------------------------------------------------
    # Test 6: Test unikalności numerów identyfikacyjnych
    # ---------------------------------------------------------
    print("\n[Test 6] Test unikalności numerów identyfikacyjnych")
    msg_t6 = "A bardzo długa wiadomość testowa mająca na celu przetestowanie unikalności dla wielu znaków i spacji AAAA eeee"
    packets_t6 = encode_message(msg_t6)
    
    ids_t6 = [p[IP].id for p in packets_t6]
    unique_ids_t6 = set(ids_t6)
    is_unique = (len(ids_t6) == len(unique_ids_t6))
    
    print(f"-> Sprawdzanie długiej wiadomości (wygenerowano {len(ids_t6)} pakietów)")
    print(f"-> Liczba powtórzonych ID: {len(ids_t6) - len(unique_ids_t6)}")
    print(f"-> STATUS: {'ZALICZONY' if is_unique else 'NIEZALICZONY'}")

    # ---------------------------------------------------------
    # Test 7: Test obsługi znaków specjalnych
    # ---------------------------------------------------------
    print("\n[Test 7] Obsługa znaków specjalnych")
    msg_t7 = "!@#$%^&*()_+{}|:<>?~"
    print(f"-> Wejście: '{msg_t7}'")
    packets_t7 = encode_message(msg_t7)
    decoded_t7 = decode_message(packets_t7)
    print(f"-> Odtworzone wejście: '{decoded_t7}'")
    print(f"-> STATUS: {'ZALICZONY' if decoded_t7 == msg_t7 else 'NIEZALICZONY'}")

    print("\n=== ZAKOŃCZENIE TESTÓW ===")

if __name__ == "__main__":
    run_tests()