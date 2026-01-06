import os
import platform
import subprocess
import hashlib
import sys
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# ----------- Device Detection -----------
def list_devices():
    system = platform.system()
    if system in ["Linux", "Darwin"]:  # macOS / Linux
        result = subprocess.run(
            ["lsblk", "-o", "NAME,SIZE,TYPE,MOUNTPOINT", "-J"],
            capture_output=True, text=True
        )
        return result.stdout
    elif system == "Windows":
        cmd = 'wmic diskdrive get Caption,DeviceID,Size /format:list'
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        return result.stdout.strip()
    else:
        return "Unsupported OS"

# ----------- File Wipe Methods -----------
def wipe_zero_fill(filepath, passes=1):
    size = os.path.getsize(filepath)
    with open(filepath, "wb") as f:
        for _ in range(passes):
            f.write(b"\x00" * size)
            f.flush()
            os.fsync(f.fileno())

def wipe_dod_3pass(filepath):
    size = os.path.getsize(filepath)
    with open(filepath, "r+b") as f:
        f.write(b"\x00" * size); f.flush(); os.fsync(f.fileno())
        f.seek(0); f.write(b"\xFF" * size); f.flush(); os.fsync(f.fileno())
        f.seek(0); f.write(os.urandom(size)); f.flush(); os.fsync(f.fileno())

def wipe_crypto_erase(filepath):
    size = os.path.getsize(filepath)
    key = os.urandom(32)  # AES-256 key
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    with open(filepath, "r+b") as f:
        while chunk := f.read(4096):
            encrypted_chunk = encryptor.update(chunk)
            f.seek(f.tell() - len(chunk))
            f.write(encrypted_chunk)
        f.flush()
        os.fsync(f.fileno())
    del key, iv

# ----------- Folder Wiping -----------
def wipe_folder_secure(folderpath, method="zero"):
    for root, dirs, files in os.walk(folderpath, topdown=False):
        for file in files:
            filepath = os.path.join(root, file)
            try:
                if method == "zero":
                    wipe_zero_fill(filepath)
                elif method == "dod":
                    wipe_dod_3pass(filepath)
                else:
                    wipe_crypto_erase(filepath)
                os.remove(filepath)
                print(f"[INFO] Wiped & deleted {filepath}")
            except Exception as e:
                print(f"⚠️ Failed wiping {filepath}: {e}")
        for d in dirs:
            try:
                os.rmdir(os.path.join(root, d))
            except Exception:
                pass
    try:
        os.rmdir(folderpath)
        print(f"[INFO] Folder {folderpath} deleted successfully.")
    except Exception as e:
        print(f"⚠️ Failed to delete {folderpath}: {e}")

# ----------- Disk Wipe (Dangerous!) -----------
def wipe_disk(device_path, method="zero"):
    print(f"⚠️  WARNING: This will wipe the ENTIRE disk: {device_path}")
    confirm = input("Type 'ERASE' to confirm: ")
    if confirm != "ERASE":
        print("❌ Operation cancelled.")
        return

    try:
        with open(device_path, "rb+") as disk:
            if method == "zero":
                print("[INFO] Writing zeros across disk...")
                while True:
                    written = disk.write(b"\x00" * 4096)
                    if not written:
                        break
            elif method == "dod":
                print("[INFO] DoD 3-pass across disk...")
                for pattern in [b"\x00", b"\xFF", None]:
                    disk.seek(0)
                    while True:
                        chunk = os.urandom(4096) if pattern is None else pattern * 4096
                        written = disk.write(chunk)
                        if not written:
                            break
            elif method == "crypto":
                print("[INFO] Crypto erase across disk...")
                key = os.urandom(32)
                iv = os.urandom(16)
                cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
                encryptor = cipher.encryptor()
                disk.seek(0)
                while True:
                    chunk = disk.read(4096)
                    if not chunk:
                        break
                    encrypted = encryptor.update(chunk)
                    disk.seek(disk.tell() - len(chunk))
                    disk.write(encrypted)
                del key, iv
            else:
                print("❌ Unknown wipe method.")
                return
    except PermissionError:
        print("❌ Permission denied! Run as administrator/root.")
    except Exception as e:
        print(f"⚠️ Disk wipe failed: {e}")
    else:
        print("✅ Disk wipe completed.")
# ----------- CLI Flow -----------
if __name__ == "__main__":
    print("🔍 Detecting connected storage devices...\n")
    devices = list_devices()
    print(devices)

    try:
        print("\nChoose target type:")
        print("1. File wipe")
        print("2. Folder wipe (recursive)")
        print("3. Whole Disk wipe (⚠️ EXTREMELY DANGEROUS)")

        choice = input("Enter choice (1/2/3): ").strip()
        if choice not in ["1", "2", "3"]:
            raise ValueError("Invalid target type selected!")

        print("\nChoose wipe method: 1) Zero-fill  2) DoD-3pass  3) CryptoErase")
        method_choice = input("Enter choice (1/2/3): ").strip()
        if method_choice not in ["1", "2", "3"]:
            raise ValueError("Invalid wipe method selected!")

        method = "zero" if method_choice == "1" else "dod" if method_choice == "2" else "crypto"

        if choice == "1":
            path = input("Enter file path: ").strip()
            if not os.path.isfile(path):
                raise FileNotFoundError("Invalid file path provided!")
            if method == "zero": wipe_zero_fill(path)
            elif method == "dod": wipe_dod_3pass(path)
            else: wipe_crypto_erase(path)
            os.remove(path)
            print("✅ File securely wiped.")

        elif choice == "2":
            folder = input("Enter folder path: ").strip()
            if not os.path.isdir(folder):
                raise FileNotFoundError("Invalid folder path provided!")
            wipe_folder_secure(folder, method)
            print("✅ Folder securely wiped.")

        elif choice == "3":
            print("\nAvailable devices (choose carefully!):")
            print(devices)
            device_path = input("Enter device path (e.g., /dev/sdb or \\\\.\\PhysicalDrive1): ").strip()
            if not device_path:
                raise ValueError("No device path entered!")
            wipe_disk(device_path, method)

    except (FileNotFoundError, ValueError) as e:
        print(f"❌ Error: {e}")
    except KeyboardInterrupt:
        print("\n⚠️ Operation cancelled by user.")
    except Exception as e:
        print(f"⚠️ Unexpected error: {e}")
