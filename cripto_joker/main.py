from models import Sobre, Tarjeta, Utilidades

if __name__ == '__main__':
    
    print("clave AES:\t" + str(Utilidades.obtener_llave_AES())+"\n\n\n")
    print("*"*120)
    print("\n")


    tarjetita = Tarjeta(mensaje= Utilidades.obtener_palabra(), clave_aes= Utilidades.obtener_llave_AES())

    print("Tarjeta:\t")
    print(tarjetita.mostrar_tarjeta())
    
    ola = Tarjeta.descifrar_mensaje(
        tarjeta= tarjetita.mostrar_tarjeta(),
        clave_aes= Utilidades.obtener_llave_AES()
    )



    print("\n\n\nMensaje original descifrado:\t" + str(ola))


###############################################################################################
###############################################################################################
###############################################################################################

sobrecito = Sobre(
    clave_aes= Utilidades.obtener_llave_AES(),
    llave_pub_rsa= Utilidades.obtener_llave_pub_rsa()
)

print("\n")
print("*"*120)
print("\n\n\Sobre:\n"+str(sobrecito.mostrar_sobre()))

print("\n\n\nclave_aes:\t:" + str(Sobre.descifrar_sobre(
    llave_priv_rsa= Utilidades.obtener_llave_priv_rsa(),
    sobre= sobrecito.mostrar_sobre()
)))



print("\n")
print("*"*120)

kase = Sobre.descifrar_sobre(
    llave_priv_rsa= Utilidades.obtener_llave_priv_rsa(),
    sobre= sobrecito.mostrar_sobre()
)

print("\nmensaje original desde el Sobre:\t"+str(Tarjeta.descifrar_mensaje(
    tarjeta= tarjetita.mostrar_tarjeta(),
    clave_aes= Sobre.descifrar_sobre(
        llave_priv_rsa= Utilidades.obtener_llave_priv_rsa(),
        sobre= sobrecito.mostrar_sobre()
    )
)))
# print("\nmensaje original desde el Sobre:\t"+str(Tarjeta.descifrar_mensaje(
#     tarjeta= tarjetita.mostrar_tarjeta(),
#     clave_aes= kase
# )))