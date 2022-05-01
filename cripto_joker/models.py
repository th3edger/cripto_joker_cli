from pathlib import Path
from random import choice

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from cryptography.fernet import Fernet

DIRECTORIO_LLAVES = Path().resolve().parent.joinpath("keys")
ARCHIVOS_GENERADOS = Path().resolve().parent.joinpath("files")
ARCHIVO_PALABRAS = Path().resolve().parent.joinpath("data")


"""
mensaje + clave_aes = TARJETA
TARJETA - clave_aes = MENSAJE
"""
class Tarjeta:
    def __init__(self, mensaje: str, clave_aes: bytes) -> None:
        self.mensaje = mensaje
        self.clave_aes = clave_aes

        self._mensaje_cifrado = None
        self._cifrar_mensaje()
        self._guardar_tarjeta()
    

    def _cifrar_mensaje(self) -> None:
        f = Fernet(self.clave_aes)
        self._mensaje_cifrado = f.encrypt(data=self.mensaje.encode())
    
    
    def _guardar_tarjeta(self) -> None:
        with open(ARCHIVOS_GENERADOS.joinpath("tarjeta.txt"),mode="wb") as f:
            f.write(self.mostrar_tarjeta())


    def mostrar_tarjeta(self) -> bytes:
        return self._mensaje_cifrado


    @staticmethod
    def descifrar_mensaje(tarjeta: bytes, clave_aes: bytes) -> bytes:
        f = Fernet(clave_aes)
        return f.decrypt(tarjeta)



"""
clave_aes + pub_rsa = SOBRE
SOBRE - priv_rsa = clave_aes
"""
class Sobre:
    def __init__(self, clave_aes: bytes, llave_pub_rsa: bytes) -> None:
        self.clave_aes = clave_aes
        self.llave_pub_rsa = llave_pub_rsa

        self._llave_aes_cifrada = None

        self._cifrar_clave_aes()
        self._guardar_sobre()


    def _guardar_sobre(self)-> None:
        with open(ARCHIVOS_GENERADOS.joinpath("sobre.txt"), mode="wb") as f:
            f.write(self.mostrar_sobre())
        

    def mostrar_sobre(self) -> bytes:
        return self._llave_aes_cifrada


    def _cifrar_clave_aes(self) -> None:
        llave_pub_rsa = RSA.import_key(self.llave_pub_rsa)
        cifrado_rsa = PKCS1_OAEP.new(llave_pub_rsa)
        cifrar_aes_con_rsa = cifrado_rsa.encrypt(self.clave_aes)

        self._llave_aes_cifrada = cifrar_aes_con_rsa


    @staticmethod
    def descifrar_sobre(llave_priv_rsa: bytes, sobre: bytes) -> bytes:
        llave_priv_rsa = RSA.import_key(llave_priv_rsa)
        cifrado = PKCS1_OAEP.new(llave_priv_rsa)

        return cifrado.decrypt(sobre)



class Utilidades:
    ### AES
    @staticmethod
    def generar_clave_AES():
        clave = Fernet.generate_key()

        with open(DIRECTORIO_LLAVES.joinpath("llave_AES.txt"), mode="wb") as f:
            f.write(clave)


    @staticmethod
    def obtener_llave_AES():
        return open(DIRECTORIO_LLAVES.joinpath("llave_AES.txt"), mode='rb').read()


    ### RSA
    @staticmethod
    def generar_llaves_RSA():
        llave = RSA.generate(1024)
        
        if not Path(DIRECTORIO_LLAVES.joinpath("llaveprivada.pem")).exists():
            with open(DIRECTORIO_LLAVES.joinpath("llaveprivada.pem"), mode="wb") as f:
                f.write(llave.export_key("PEM"))


        if not Path(DIRECTORIO_LLAVES.joinpath("llavepublica.pub")).exists():
            with open(DIRECTORIO_LLAVES.joinpath("llavepublica.pub"), mode="wb") as f:
                f.write(llave.public_key().export_key("PEM"))
    

    @staticmethod
    def obtener_llave_priv_rsa():
        return open(DIRECTORIO_LLAVES.joinpath("llaveprivada.pem"), mode="rb").read()


    @staticmethod
    def obtener_llave_pub_rsa():
        return open(DIRECTORIO_LLAVES.joinpath("llavepublica.pub"), mode="rb").read()
    

    #Seleccionar Mensaje
    @staticmethod
    def obtener_palabra():
        with open(ARCHIVO_PALABRAS.joinpath("mensajes.txt"), mode="r") as f:
            palabra = choice(f.readlines())

            return palabra.strip()
