# Release Date API

## Getting Started
To use the application 3 services must be started:
- authentication/auth_server.py
- server/server-chat.py
- client/client-chat.py

To start the services run the following command in order in separate terminal windows:
```
python auth_server.py
python server-chat.py
python client-chat.py
```

The client chat will ask for authentication or registration, after that you will enter the chat room.

To receive chat messages in the chat room, press enter without entering message text.

To connect other clients to the chat room, open more terminal windows and run `python client-chat.py` with a different user logged in or registered.

Users can be deleted by selecting "no" in the login flow.
