import nfc

try:
    clf = nfc.ContactlessFrontend('usb')
    print("NFC reader initialized successfully!")
    clf.close()
except Exception as e:
    print(f"Error: {e}")
