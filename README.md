# steg-lab5-IP

# Laboratorium 5

## Instructions

# Implementacja ukrytego kanału komunikacyjnego w protokole IP

Celem tego zadania jest implementacja prostego ukrytego kanału komunikacyjnego wykorzystującego pole identyfikacji w nagłówku protokołu IP. Zadanie ma na celu praktyczne zastosowanie wiedzy o steganografii sieciowej i protokole IP.

## Opis zadania

Zaimplementuj program w języku Python, który będzie:

1. Generował pakiety IP z ukrytymi danymi w polu identyfikacji.
2. Odczytywał ukryte dane z odebranych pakietów IP.

## Wymagania

1. Program powinien wykorzystywać bibliotekę Scapy do tworzenia i analizy pakietów IP.
2. Implementacja powinna zawierać dwie główne funkcje:
   - `encode_message(message)`: Funkcja kodująca wiadomość w pakietach IP.
   - `decode_message(packets)`: Funkcja dekodująca wiadomość z pakietów IP.
3. Program powinien obsługiwać wiadomości tekstowe o długości do 1000 znaków.
4. Implementacja powinna zapewniać unikalność numerów identyfikacyjnych w ramach jednej transmisji.

## Kryteria akceptacji

1. Program poprawnie koduje wiadomość w polu identyfikacji pakietów IP.
2. Program poprawnie dekoduje wiadomość z odebranych pakietów IP.
3. Implementacja zapewnia unikalność numerów identyfikacyjnych.

## Przypadki testowe

1. Test kodowania krótkiej wiadomości (do 2 znaków):
   - Wejście: `"IT"`
   - Oczekiwany wynik: Jeden pakiet IP z zakodowaną wiadomością w polu identyfikacji.

2. Test kodowania długiej wiadomości (powyżej 2 znaków):
   - Wejście: `"This is a longer message that requires multiple packets to encode."`
   - Oczekiwany wynik: Seria pakietów IP z zakodowaną wiadomością w polach identyfikacji.

3. Test dekodowania wiadomości z pojedynczego pakietu:
   - Wejście: Pakiet IP z zakodowaną wiadomością `"IT"`
   - Oczekiwany wynik: `"IT"`

4. Test dekodowania wiadomości z wielu pakietów:
   - Wejście: Seria pakietów IP z zakodowaną długą wiadomością
   - Oczekiwany wynik: Oryginalna długa wiadomość

5. Test obsługi pustej wiadomości:
   - Wejście: `""`
   - Oczekiwany wynik: Brak wygenerowanych pakietów lub odpowiedni komunikat o błędzie

6. Test unikalności numerów identyfikacyjnych:
   - Wejście: Długa wiadomość wymagająca wielu pakietów
   - Oczekiwany wynik: Wszystkie wygenerowane pakiety mają unikalne numery identyfikacyjne

7. Test obsługi znaków specjalnych:
   - Wejście: `"!@#$%^&*()_+{}|:<>?~"`
   - Oczekiwany wynik: Poprawne zakodowanie i dekodowanie wiadomości ze znakami specjalnymi

## Wskazówki implementacyjne

1. Wykorzystaj bibliotekę Scapy do tworzenia i manipulacji pakietami IP.
2. Zastosuj odpowiednie kodowanie (np. ASCII lub UTF-8) do konwersji znaków na liczby.
3. Pamiętaj o ograniczeniu 16-bitowym pola identyfikacji (wartości od 0 do 65535).
4. Zaimplementuj mechanizm zapewniający unikalność numerów identyfikacyjnych, np. poprzez inkrementację lub losowanie z puli niewykorzystanych numerów.
5. Dodaj obsługę błędów dla przypadków takich jak pusta wiadomość czy przekroczenie maksymalnej długości wiadomości.
