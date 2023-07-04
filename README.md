# Vocalhost

Vocalhost is a communication solution that enables direct and reliable connections between systems using WebSocket protocol. It comprises a bridge server and a client agent, offering support for a wide range of languages, frameworks, and systems. This versatility allows for seamless interaction and efficient data exchange across diverse environments.

The bridge server acts as a central hub, relaying real-time messages between connected systems over WebSocket connections. The client agent establishes a WebSocket connection with the bridge server, facilitating communication across various platforms.

Vocalhost simplifies system-to-system interaction, providing compatibility and ease of use across different languages, frameworks, and systems. This promotes streamlined data exchange.

## Getting Started
Vocalhost is a communication solution that enables direct and reliable connections between systems using the WebSocket protocol. It consists of a bridge server and two client agents: VocalhostReceiver and VocalhostRequest.

#### Install the Vocalhost library:
pip install vocalhost

## VocalhostReceiver
The VocalhostReceiver client establishes a WebSocket connection with the bridge server and keeps the connection open to receive incoming messages. It processes the received messages and generates a response.

Import the necessary modules:
```python
from vocalhost import Receiver
```
Define a function to process the received messages and generate a response:

```python
def process_message(message):
    # Process the received message and generate a response
    # Implement your custom logic here
    print("Received message from VocalhostRequest:", message)
    # Generate the response
    response = "This is the response from the VocalhostReceiver"
    return response
```
Create an instance of the VocalhostReceiver and provide the process_message function as an argument:
```python
client_id = 'Your CLIENT ID or NAME'
receiver = Receiver(process_message=process_message, client_id, API_KEY)
```
Connect to the Vocalhost bridge server:
```python
receiver.connect()
```
The VocalhostReceiver client will establish a WebSocket connection with the bridge server and start listening for incoming messages. When a message is received, the process_message function will be invoked to process the message and generate a response.

## VocalhostRequest
The VocalhostRequest client is used to send HTTP POST requests to the Vocalhost bridge server, which will forward the requests to the VocalhostReceiver client. The VocalhostReceiver client will process the request, generate a response, and send it back to the bridge server. The bridge server will then respond to the VocalhostRequest client with the received response.

Import the necessary modules:
```python
from vocalhost import Request
```
Create an instance of Request:
```python
requests = Request(API_KEY)
```
Send and data:
```python
message = 'How about a game of chess?'
response = requests.send(message, receiver_id)
```
Process the response received from the bridge server:
```python
print(response.text)
```
The VocalhostRequest client sends an HTTP POST request to the Vocalhost bridge server, specifying the URL of the VocalhostReceiver client to connect to. The bridge server will forward the request to the VocalhostReceiver client, which will process the request and generate a response. The response will be sent back to the bridge server, and the bridge server will respond to the VocalhostRequest client with the received response.

With Vocalhost, you can streamline system communication by establishing WebSocket connections between systems, enabling real-time message exchange and seamless interaction across different languages, frameworks, and systems.


For features and documentation please visit [Documentation](https://vocalhost.reiserx.com/) 
