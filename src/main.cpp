#include <Arduino.h>
#include <PN532.h>
#include <LiquidCrystal_I2C.h>
using namespace std;
// #define SPI_MODE

#ifdef SPI_MODE
#include <SPI.h>
#include <PN532_SPI.h>
PN532_SPI pn532spi(SPI, D0);
PN532 nfc(pn532spi);
#else
#include <Wire.h>
#include <PN532_I2C.h>
#define relay1 D6
#define relay2 D7
PN532_I2C pn532_i2c(Wire);
PN532 nfc(pn532_i2c);
#endif

LiquidCrystal_I2C lcd(0x27, 16, 2);
unsigned long previousMillis = 0;
const long interval = 100; // interval in ms

void GenerateKeyA(uint8_t *uid, uint8_t uidLength, uint8_t *static_key, uint8_t *result);
void Reverse(const char *original, char *reverse, int size);
::byte nibble(char c);
void dumpByteArray(const ::byte *byteArray, const ::byte arraySize);
void hexCharacterStringToBytes(::byte *byteArray, const char *hexString);

void setup()
{
  Serial.begin(115200);

  lcd.init();
  lcd.backlight();
  lcd.begin(16, 2);

  Serial.println("Hello!");
  lcd.setCursor(1, 0);
  lcd.print("Hello :)");
  delay(3000);
  lcd.clear();
  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata)
  {
    Serial.print("Didn't find PN53x board");
    lcd.setCursor(0, 0);
    lcd.print("Didn't find PN53x board");
    while (1)
      delay(100); // halt
  }
  // Got ok data, print it out!
  Serial.print("Found chip PN5");
  Serial.println((versiondata >> 24) & 0xFF, HEX);
  Serial.print("Firmware ver. ");
  Serial.print((versiondata >> 16) & 0xFF, DEC);
  Serial.print('.');
  Serial.println((versiondata >> 8) & 0xFF, DEC);

  // configure board to read RFID tags
  nfc.SAMConfig();

  Serial.println("Waiting for an ISO14443A Card ...");
  pinMode(relay1, OUTPUT);
  pinMode(relay2, OUTPUT);
}

void loop()
{
  lcd.clear();
  uint8_t success;
  uint8_t uid[] = {0, 0, 0, 0, 0, 0, 0}; // Buffer to store the returned UID
  uint8_t uidLength;                     // Length of the UID (4 or 7 bytes depending on ISO14443A card type)

  // Wait for an ISO14443A type cards (Mifare, etc.).  When one is found
  // 'uid' will be populated with the UID, and uidLength will indicate
  // if the uid is 4 bytes (Mifare Classic) or 7 bytes (Mifare Ultralight)
  success = nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 10);
  // print 0000
  if (success)
  {
    // Display some basic information about the card
    Serial.println("Found an ISO14443A card");
    Serial.print("  UID Length: ");
    Serial.print(uidLength, DEC);
    Serial.println(" bytes");
    Serial.print("  UID Value: ");
    nfc.PrintHex(uid, uidLength);
    Serial.println("");
    digitalWrite(relay1, LOW);
    lcd.setCursor(0, 0);
    lcd.print("Success");
    delay(4000);
    lcd.clear();

    if (uidLength == 4)
    {
      // We probably have a Mifare Classic card ...
      Serial.println("Seems to be a Mifare Classic card (4 byte UID)");

      // Now we need to try to authenticate it for read/write access
      // Try with the factory default KeyA: 0xFF 0xFF 0xFF 0xFF 0xFF 0xFF
      Serial.println("Trying to authenticate block 4 with default KEYA value");
      // uint8_t keya[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
      uint8_t keya[6];
      uint8_t static_key[2] = {20, 21};
      GenerateKeyA(uid, uidLength, static_key, keya);
      nfc.PrintHex(keya, 6);
      Serial.println();

      // Start with block 4 (the first block of sector 1) since sector 0
      // contains the manufacturer data and it's probably better just
      // to leave it alone unless you know what you're doing
      success = nfc.mifareclassic_AuthenticateBlock(uid, uidLength, 4, 0, keya);
      digitalWrite(relay1, LOW);
      lcd.setCursor(0, 0);
      lcd.print("Success");
      delay(4000);
      lcd.clear();
      Serial.print(success);
      if (success)
      {
        Serial.println("Sector 1 (Blocks 4..7) has been authenticated");
        uint8_t data[16];
        uint8_t data_card[32];

        // If you want to write something to block 4 to test with, uncomment
        // the following line and this text should be read back in a minute
        // data = { 'a', 'd', 'a', 'f', 'r', 'u', 'i', 't', '.', 'c', 'o', 'm', 0, 0, 0, 0};
        // success = nfc.mifareclassic_WriteDataBlock (4, data);

        // Try to read the contents of block 4
        success = nfc.mifareclassic_ReadDataBlock(5, data);
        digitalWrite(relay1, LOW);
        lcd.setCursor(0, 0);
        lcd.print("Success");
        delay(4000);
        lcd.clear();

        if (success)
        {
          for (size_t i = 0; i < 16; i++)
            data_card[i] = data[i];

          // Data seems to have been read ... spit it out
          Serial.println("Reading Block 5:");
          nfc.PrintHexChar(data, 16);
          Serial.println("");

          // Wait a bit before reading the card again
          // delay(500);
          success = nfc.mifareclassic_ReadDataBlock(6, data);
          digitalWrite(relay1, LOW);
          lcd.setCursor(0, 0);
          lcd.print("Success");
          delay(4000);
          lcd.clear();

          if (success)
          {
            for (size_t i = 16; i < 32; i++)
              data_card[i] = data[i - 16];

            Serial.println("Reading Block 6:");
            nfc.PrintHexChar(data, 16);
            Serial.println("");
            nfc.PrintHexChar(data_card, 32);
            Serial.println("");

            uint8_t nip[18];
            String strNip;
            for (size_t i = 0; i < 18; i++)
            {
              nip[i] = data_card[i + 1];
              strNip += String((char)nip[i]);
            }
            nfc.PrintHexChar(nip, 18);
            Serial.println("");
            Serial.println(strNip);
            digitalWrite(relay1, LOW);
            lcd.print("Success");
            delay(4000);
            lcd.clear();
          }
          else
          {
            Serial.println("Ooops ... unable to read the requested block.  Try another key?");
            digitalWrite(relay1, HIGH);
            lcd.setCursor(0, 0);
            lcd.print("Failed");
            // lcd.scrollDisplayLeft();
            delay(4000);
            return;
          }
        }
        else
        {
          Serial.println("Ooops ... unable to read the requested block.  Try another key?");
          digitalWrite(relay1, HIGH);
          lcd.setCursor(0, 0);
          lcd.print("Failed");
          // lcd.scrollDisplayLeft();
          delay(4000);
          return;
        }
      }
      else
      {
        Serial.println("Ooops ... authentication failed: Try another key?");
        digitalWrite(relay1, HIGH);
        lcd.setCursor(0, 0);
        lcd.print("Failed");
        // lcd.scrollDisplayLeft();
        delay(4000);
        return;
      }
    }
  }
}

void Reverse(const char *original, char *reverse, int size)
{
  if (size > 0 && original != NULL && reverse != NULL)
  {
    for (int i = 0; i < size; ++i)
    {
      reverse[i] = original[size - i - 2];
    }

    reverse[size - 1] = '\0';
  }
}

void hexCharacterStringToBytes(::byte *byteArray, const char *hexString)
{
  bool oddLength = strlen(hexString) & 1;

  ::byte currentByte = 0;
  ::byte byteIndex = 0;

  for (::byte charIndex = 0; charIndex < strlen(hexString); charIndex++)
  {
    bool oddCharIndex = charIndex & 1;

    if (oddLength)
    {
      // If the length is odd
      if (oddCharIndex)
      {
        // odd characters go in high nibble
        currentByte = nibble(hexString[charIndex]) << 4;
      }
      else
      {
        // Even characters go into low nibble
        currentByte |= nibble(hexString[charIndex]);
        byteArray[byteIndex++] = currentByte;
        currentByte = 0;
      }
    }
    else
    {
      // If the length is even
      if (!oddCharIndex)
      {
        // Odd characters go into the high nibble
        currentByte = nibble(hexString[charIndex]) << 4;
      }
      else
      {
        // Odd characters go into low nibble
        currentByte |= nibble(hexString[charIndex]);
        byteArray[byteIndex++] = currentByte;
        currentByte = 0;
      }
    }
  }
}

void dumpByteArray(const ::byte *byteArray, const ::byte arraySize)
{

  for (int i = 0; i < arraySize; i++)
  {
    Serial.print("0x");
    if (byteArray[i] < 0x10)
      Serial.print("0");
    Serial.print(byteArray[i], HEX);
    Serial.print(", ");
  }
  Serial.println();
}

::byte nibble(char c)
{
  if (c >= '0' && c <= '9')
    return c - '0';

  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;

  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;

  return 0; // Not a valid hexadecimal character
}

void GenerateKeyA(uint8_t *uid, uint8_t uidLength, uint8_t *static_key, uint8_t *result)
{
  Serial.println("GenreateKey A start");
  nfc.PrintHex(uid, uidLength);
  memcpy(result, uid, uidLength);
  String CardID = "";
  for (::byte i = 0; i < uidLength; i++)
  {
    String rs = String(uid[i], HEX);
    if (rs.length() == 1)
    {
      rs = "0" + rs;
    }
    CardID += rs;
  }
  Serial.println(CardID);
  char reverse[CardID.length()];
  Reverse(CardID.c_str(), reverse, CardID.length() + 1);
  String rev = String(reverse);
  Serial.println(rev);
  Serial.println("GenreateKey A end");
  lcd.clear();

  ::byte arr[rev.length() / 2];
  hexCharacterStringToBytes(arr, rev.c_str());
  dumpByteArray(arr, rev.length() / 2);

  ::byte key[6];
  key[0] = static_key[0];
  key[1] = arr[0];
  key[2] = arr[1];
  key[3] = arr[2];
  key[4] = arr[3];
  key[5] = static_key[1];
  dumpByteArray(key, 6);

  for (size_t i = 0; i < 6; i++)
    result[i] = key[i];
}