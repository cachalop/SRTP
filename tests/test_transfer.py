import subprocess
import sys
import time


# Transfert simple d’un petit fichier texte
def test_transfer(tmp_path):
    root = tmp_path / "root"
    root.mkdir()

    src_file = root / "file.txt"
    src_file.write_bytes(b"hello world")

    out_file = tmp_path / "out.txt"

    server = subprocess.Popen(
        [sys.executable, "src/server.py", "::1", "9091", "--root", str(root)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        time.sleep(0.5)

        result = subprocess.run(
            [
                sys.executable,
                "src/client.py",
                "http://[::1]:9091/file.txt",
                "--save",
                str(out_file),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )

        assert result.returncode == 0
        assert out_file.read_bytes() == src_file.read_bytes()

    finally:
        server.kill()
        server.wait()


# Vérifie le cas d’un fichier vide
def test_transfer_empty_file(tmp_path):
    root = tmp_path / "root"
    root.mkdir()

    src_file = root / "empty.txt"
    src_file.write_bytes(b"")

    out_file = tmp_path / "out_empty.txt"

    server = subprocess.Popen(
        [sys.executable, "src/server.py", "::1", "9092", "--root", str(root)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        time.sleep(0.5)

        result = subprocess.run(
            [
                sys.executable,
                "src/client.py",
                "http://[::1]:9092/empty.txt",
                "--save",
                str(out_file),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )

        assert result.returncode == 0
        assert out_file.read_bytes() == b""

    finally:
        server.kill()
        server.wait()


# Si le fichier n’existe pas, le client doit terminer proprement
def test_transfer_missing_file(tmp_path):
    root = tmp_path / "root"
    root.mkdir()

    out_file = tmp_path / "missing_out.txt"

    server = subprocess.Popen(
        [sys.executable, "src/server.py", "::1", "9093", "--root", str(root)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        time.sleep(0.5)

        result = subprocess.run(
            [
                sys.executable,
                "src/client.py",
                "http://[::1]:9093/does_not_exist.txt",
                "--save",
                str(out_file),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )

        assert result.returncode == 0
        assert out_file.exists()
        assert out_file.read_bytes() == b""

    finally:
        server.kill()
        server.wait()


# Taille exacte d’un payload maximal
def test_transfer_1024_bytes(tmp_path):
    root = tmp_path / "root"
    root.mkdir()

    src_file = root / "f1024.bin"
    src_file.write_bytes(b"A" * 1024)

    out_file = tmp_path / "out1024.bin"

    server = subprocess.Popen(
        [sys.executable, "src/server.py", "::1", "9094", "--root", str(root)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        time.sleep(0.5)

        result = subprocess.run(
            [
                sys.executable,
                "src/client.py",
                "http://[::1]:9094/f1024.bin",
                "--save",
                str(out_file),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )

        assert result.returncode == 0
        assert out_file.read_bytes() == src_file.read_bytes()

    finally:
        server.kill()
        server.wait()


# Un octet de plus que la taille maximale d’un segment
def test_transfer_1025_bytes(tmp_path):
    root = tmp_path / "root"
    root.mkdir()

    src_file = root / "f1025.bin"
    src_file.write_bytes(b"B" * 1025)

    out_file = tmp_path / "out1025.bin"

    server = subprocess.Popen(
        [sys.executable, "src/server.py", "::1", "9095", "--root", str(root)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        time.sleep(0.5)

        result = subprocess.run(
            [
                sys.executable,
                "src/client.py",
                "http://[::1]:9095/f1025.bin",
                "--save",
                str(out_file),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )

        assert result.returncode == 0
        assert out_file.read_bytes() == src_file.read_bytes()

    finally:
        server.kill()
        server.wait()


# Taille non limite mais proche d’un paquet
def test_transfer_1000_bytes(tmp_path):
    root = tmp_path / "root"
    root.mkdir()

    src_file = root / "f1000.bin"
    src_file.write_bytes(b"C" * 1000)

    out_file = tmp_path / "out1000.bin"

    server = subprocess.Popen(
        [sys.executable, "src/server.py", "::1", "9096", "--root", str(root)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        time.sleep(0.5)

        result = subprocess.run(
            [
                sys.executable,
                "src/client.py",
                "http://[::1]:9096/f1000.bin",
                "--save",
                str(out_file),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )

        assert result.returncode == 0
        assert out_file.read_bytes() == src_file.read_bytes()

    finally:
        server.kill()
        server.wait()


# Vérifie un transfert sur plusieurs segments
def test_transfer_larger_file(tmp_path):
    root = tmp_path / "root"
    root.mkdir()

    src_file = root / "big.bin"
    src_file.write_bytes(b"XYZ123" * 2000)

    out_file = tmp_path / "big_out.bin"

    server = subprocess.Popen(
        [sys.executable, "src/server.py", "::1", "9097", "--root", str(root)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    try:
        time.sleep(0.5)

        result = subprocess.run(
            [
                sys.executable,
                "src/client.py",
                "http://[::1]:9097/big.bin",
                "--save",
                str(out_file),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=15,
        )

        assert result.returncode == 0
        assert out_file.read_bytes() == src_file.read_bytes()

    finally:
        server.kill()
        server.wait()