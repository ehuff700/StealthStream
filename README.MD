# Documentation for StealthStream Protocol

## Framing:
The underlying communication of a StealthStream connection is based on the concept of **Frames**. Frames are defined as a sequence of bytes which represent the following:
1. The length prefix of the frame.
2. The message type that the frame represents.
2. The type of frame this is (e.g Continuation, End, etc.), hereby known as a Frame Flag
3. The actual message content itself.

### Frame Categories
Frames are broken into two categories, with distinct meaning.
* `DATA FRAMES`
  - Data frames **DO** support fragmentation
  - Data frames **DO** support the Beginning, Continuation, and End frame flags, to support fragmentation.
  - Data frames are expected to be large in size, and are the primary means of communication between client and server.
* `CONTROL FRAMES`
  - Control frames **DO NOT** support fragmentation
  - Control frames **DO NOT** support the Beginning, Continuation, and End frame flags, and **MUST** always be sent with the Frame Flag of "Complete". 
  - Control frames are expected to be very small in size, ranging from 1 to ~10 bytes.
  - Control frames are used to control the connection, e.g `Heartbeat`, `Goodbye` and `Handshake` messages.

### Frame Opcodes
Frame opcodes are a single byte used to denote the type of message that is being sent. Frame opcodes are divided into the categories above.
A list of `DATA FRAMES` opcodes are:
1. `Message` | `0x3` - Used to transfer utf-8 or non-utf-8 bytes.
2. `Acknolwedgement` | `0x4` - Used to acknowledge previously sent frames (e.g request/response cycle).

A list of `CONTROL FRAMES` opcodes are:
1. `Goodbye` | `0x2` - Used to close the connection bi-directionally (ideally) with a mandatory close code and optional reason.
2. `Handshake` | `0x0` - Used during connection initialization to identify the stream as a StealthStream and upgrade the connection. In the future will be used to configure compression and TLS cipher suites.
3. `Heartbeat` | `0x1` - Used for keep-alive, especially in situations where one of the hosts is behind a NAT.
4. `Error` | `0x5` - Used to send errors with a mandatory code and mandatory reason.

### Frame Flags
1. `Beginning`
   - This represents the beginning of a stream of fragmented frames. Only supported by Data Frames.
2. `Continuation`
   - This represents the continuation of a stream of fragmented frames. Only supported by Data Frames.
3. `End`
   - This represents the end of a stream of fragmented frames, and upon concatenation with beginning frames and continuation frames, can be returned as a complete `Message`. Only supported by Data Frames.
4. `Complete`
   - This represents a complete `Message`. **BOTH** Control Frames **AND** Data Frames can have a frame flag of `Complete`.

### Reading a Frame
Frames are broken down into two primary sections, the `Header` and the `Contents`.
* `Header`:
  - The header of the frame is expected to be at minimum 6 bytes in length and at maximum 22 bytes in length.
  - The first *4* bytes of the header are the `Length Prefix` of the frame **CONTENTS**. Servers **SHOULD** set a maximum accepted length for a frame.
  - The next *single* byte of the header represents the `Frame Opcode`.
  - The next *single* byte of the header represents the `Frame Flag`
  - If the frame is a fragmented one (e.g the flag is one of `Beginning`, `Continuation`, or `End`), then the next *16* bytes of the header represent the byte representation of a Version 4 UUID, also known as the `Frame Identifier`. These identifiers are used by the server to cache frame state, and allow for interleaved fragmented frames, as opposed to Websockets which is limited to only one fragmentation at at time.

* `Contents`:
  - The contents are the arbitrary message content that are included as required by the `Frame Opcode`. Some zero-sized messages (e.g `Heartbeat`) do not have any content.
  - For non zero-sized messages, after parsing all information in the header, the server is expected to read all bytes corresponding to the `Length Prefix`. Any remaining bytes should be treated as a new message or discarded if invalid. 
  - In the case of fragmented frames, the server **MUST** store the state of the frames in a key-value buffer, where the key is the `Frame Identifier`, and the value is a continguous and growable array. `Beginning` frames will result in a new entry in the key-value buffer. When (or if) a `Continuation` frame is received, it will check the key-value buffer for the `Frame Identifier`, and concatenate its contents to the existing ones, if present. Upon receipt of an `End` frame, the key-value pair is removed from the buffer, contents are concatenated as needed, and the contents should be returned as a `Message`.  
  - In the event that a `Continuation` or `End` frame is received, but the `Frame Identifier` is not present in the key-value buffer, the server **SHOULD** log this error, and discard the packets.
  - The server **MUST** set a reasonable TTL on keys in the key-value buffer **AND** a reasonable max message content length, to prevent both stale keys (which would lead to a memory leak) and buffer overflow attacks (e.g sending a beginning frame with infinite continuation frames).