/* Opcode Consts */
pub const HANDSHAKE_OPCODE: u8 = 0x0;
pub const POKE_OPCODE: u8 = 0x1;
pub const MESSAGE_OPCODE: u8 = 0x2;
pub const GOODBYE_OPCODE: u8 = 0x3;

/* Goodbye Codes */
/// Indicates a graceful connection closure initiated by the client or the
/// server.
pub const GRACEFUL: u8 = 100;
/// Sent by the server to indicate a server restart.
pub const SERVER_RESTARTING: u8 = 101;
/// Sent by the server if the handshake failed / was invalid.
pub const INVALID_HANDSHAKE: u8 = 102;
/// Catch all code.
pub const UNKNOWN: u8 = 0;

/* Handshake Constants */
/// The list of supported versions for the Stealth Stream Protocol.
pub const SUPPORTED_VERSIONS: [u8; 1] = [1];
/// Default handshake length for the Stealth Stream Protocol.
pub const DEFAULT_HANDSHAKE_LENGTH: usize = 1;
/// Handshake length for the Stealth Stream Protocol with a session ID.
pub const HANDSHAKE_LENGTH_WITH_SESSION_ID: usize = DEFAULT_HANDSHAKE_LENGTH + 16;
