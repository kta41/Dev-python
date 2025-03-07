import socket

target_host = "127.0.0.1"
target_port = 9998

#Creando el socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# AF_INET significa que vamos a usar una direccion IPv4 o un hostname. 
#SOCK_STREAM significa que va a ser un cliente TCP



#Conectando el cliente
client.connect((target_host,target_port))

#Enviando info
client.send(b"GET / HTTP/1.1\r\nHost: Localhost\r\n\r\nComunicación establecida\r\n\r\n")

#Recibiendo info
response = client.recv(4096)

print(response.decode())
client.close()
