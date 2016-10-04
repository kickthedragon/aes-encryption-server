//! AES Encryption Server.
//!
//! This crate is an aes encryption server. It is in charge of encrypting and decrypting all the
//! OAuth tokens sent to the server.
//!
//! The servers uses a simple TCP protocol. Messages are composed with a 5 byte header, where the
//! first byte is the method to use (AES encryption, AES decryption), and the other 4 are the big
//! endian representation of the message length.
//!
//! The rest of the message must contain exactly that length of bytes representing the data to be
//! processed.
//!
//! The response can be one of `OK`, or `ERR`. In the case of `OK`, the response will contain a 5
//! byte header composed of a `0x00` byte followed by the length of the response in 4 big endian
//! bytes. In the case of error, only the byte `0xFF` will be returned.
//!
//! The server can be configured using the provided `Cargo.toml` file. The file is a configuration
//! file written in [TOML] (https://github.com/toml-lang/toml), and its structure is the following:
//!
//! ```toml
//! socket_address = "0.0.0.0:31415" # The address and port the encryption server will listen in.
//! logs_folder = "logs" # The logs folder: this will be where logs will be located.
//! keys_folder = "keys" # The key folder: keys will be stored here.
//! server_log = "server-{}.log" # Server log, for logging requests and responses.
//! security_log = "security-{}.log" # Security log, to log security issues.
//! aes_key_file = "aes.key" # AES key file: this will be the AES key file inside `keys_folder`.
//! ```
//!
//! The keys will be generated the first time the program is run. That way, there is no need to
//! transport them from another place if its not a migration.

#![forbid(missing_docs, warnings)]
#![deny(deprecated, drop_with_repr_extern, improper_ctypes,
        non_shorthand_field_patterns, overflowing_literals, plugin_as_library,
        private_no_mangle_fns, private_no_mangle_statics, stable_features, unconditional_recursion,
        unknown_lints, unused_allocation, unused_attributes,
        unused_comparisons, unused_features, unused_parens, while_true)]
#![warn(trivial_casts, trivial_numeric_casts, unused, unused_extern_crates,
        unused_import_braces, unused_qualifications, unused_results, variant_size_differences)]

extern crate toml;
extern crate mioco;
extern crate crypto;
extern crate rand;
extern crate chrono;
extern crate byteorder;

use std::net::{Ipv4Addr, SocketAddr, AddrParseError, SocketAddrV4, Shutdown};
use std::error::Error as StdErr;
use std::{fs, io, fmt};
use std::io::{Read, Write};
use std::path::Path;
use std::sync::Arc;
use std::str::FromStr;

use toml::{Parser, ParserError, Value};
use rand::Rng;
use rand::os::OsRng;
use crypto::aes::KeySize;
use chrono::offset::utc::UTC;
use mioco::tcp::TcpListener;
use byteorder::{NetworkEndian, ByteOrder};

const CONFIG_FILE: &'static str = "Config.toml";
const AES_KEY_SIZE: usize = 256 / 8;

/// AES encryption header.
pub const HEAD_AES_ENCRYPT: u8 = 0x92;
/// AES decryption header.
pub const HEAD_AES_DECRYPT: u8 = 0x01;

const HEADERS: [u8; 2] = [HEAD_AES_ENCRYPT, HEAD_AES_DECRYPT];

/// `OK` response header
pub const CODE_OK: u8 = 0x00;
/// `ERR` response header
pub const CODE_ERR: u8 = 0xFF;

fn main() {
    if ![128 / 8, 192 / 8, 256 / 8].contains(&AES_KEY_SIZE) {
        panic!("Key size is not valid!");
    }
    let config = Arc::new(Config::load().expect("An error occurred loading the config file"));

    if !keys_exist(&config) {
        generate_keys(&config).expect("An error occurred generating the keys");
    }

    let aes_key = load_aes_key(&config).expect("An error occurred loading the AES key");

    mioco::start(move || -> Result<()> {
            let listener = try!(TcpListener::bind(&config.get_socket_addr()));

            try!(log(&config,
                     format!("Starting server in {:?}", try!(listener.local_addr()))));
            loop {
                let mut connection = try!(listener.accept());


                let config = config.clone();


                let _ = mioco::spawn(move || -> Result<()> {
                    let mut buf = [0u8; 5];

                    loop {
                        // Read header
                        if let Err(_) = connection.read_exact(&mut buf[0..5]) {
                            return Ok(());
                        }

                        // Check if the header is a valid header
                        if !HEADERS.contains(&buf[0]) {
                            try!(security_log(&config,
                                              format!("Unrecognized head: {:#02X}. Remote \
                                                       socket: {}",
                                                      buf[0],
                                                      try!(connection.peer_addr()))));
                            try!(connection.shutdown(Shutdown::Both));
                            return Ok(());
                        }

                        // Set head and packet size variables
                        let head = buf[0];
                        let size = NetworkEndian::read_u32(&buf[1..]) as usize;
                        if size == 0 {
                            // The message size is zero
                            try!(connection.shutdown(Shutdown::Both));

                            try!(security_log(&config,
                                              format!("ERROR - message size is zero. - Request \
                                                       from {}, head: {:#02X}, size: 0, \
                                                       message: []",
                                                      try!(connection.peer_addr()),
                                                      head)));


                            return Ok(());
                        }

                        // Allocate the complete message buffer
                        let mut complete_buf = vec![0u8; size];

                        // Read all the message
                        if let Err(e) = connection.read_exact(&mut complete_buf) {
                            try!(log(&config,
                                     format!("ERROR - could not read complete message: {}", e)));
                            try!(connection.shutdown(Shutdown::Both));

                            try!(log(&config,
                                     format!("Request from {}, head: {:#02X}, size: 0, \
                                              message: []",
                                             try!(connection.peer_addr()),
                                             head)));
                            return Ok(());
                        }

                        // Get the result depending on the head
                        let result = match head {
                            // Encrypt the given message using AES
                            HEAD_AES_ENCRYPT => {
                                // Generate a random iv
                                let mut iv = [0; AES_KEY_SIZE];
                                let mut rng = try!(OsRng::new());
                                rng.fill_bytes(&mut iv);

                                // Start the CTR cypher
                                let mut ctr = crypto::aes::ctr(aes_key_size(), &aes_key, &iv);

                                // Prepend the iv to the result
                                let mut result = Vec::from(&iv[..]);

                                // Append the encryption buffer and we process it
                                result.append(&mut vec![0u8; complete_buf.len()]);
                                ctr.process(&complete_buf, &mut result[AES_KEY_SIZE..]);

                                result.into_boxed_slice()
                            }
                            // Decrypt the given message using AES
                            HEAD_AES_DECRYPT => {
                                if complete_buf.len() <= AES_KEY_SIZE {
                                    // The message only contains the iv, or maybe not even that
                                    try!(log(&config,
                                             format!("ERROR - Error decrypting message. \
                                                      Message: {:?}, Error: message too short.",
                                                     complete_buf)));
                                    Box::new([CODE_ERR])
                                } else {
                                    // Initialize the CTR cypher
                                    let mut ctr = crypto::aes::ctr(aes_key_size(),
                                                                   &aes_key,
                                                                   &complete_buf[..AES_KEY_SIZE]);
                                    // Initialize the result vector
                                    let mut result = vec![0u8; complete_buf.len()-AES_KEY_SIZE];

                                    // Process the data
                                    ctr.process(&complete_buf[AES_KEY_SIZE..], &mut result);

                                    result.into_boxed_slice()
                                }
                            }
                            _ => unreachable!(),
                        };

                        if result.len() == 0 {
                            try!(connection.write_all(&[CODE_ERR]));
                            try!(connection.flush());

                            try!(log(&config,
                                     format!("Request from {}, head: {:#02X}, message: {:?}, \
                                              response_head: CODE_ERR",
                                             try!(connection.peer_addr()),
                                             head,
                                             complete_buf)));
                        } else {
                            let mut result_buf = [CODE_OK, 0, 0, 0, 0];
                            NetworkEndian::write_u32(&mut result_buf[1..], result.len() as u32);

                            let _ = try!(connection.write_all(&result_buf));
                            let _ = try!(connection.write_all(&result));
                            try!(connection.flush());
                        }

                    }
                });
            }
        })
        .unwrap()
        .unwrap();
}

/// Errors produced on the encryption server;
#[derive(Debug)]
enum Error {
    /// I/O error
    IO(io::Error),
    Config,
    Parser(Vec<ParserError>),
    AddrParse(AddrParseError),
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Error {
        Error::IO(error)
    }
}

impl From<AddrParseError> for Error {
    fn from(error: AddrParseError) -> Error {
        Error::AddrParse(error)
    }
}


impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.description())
    }
}

impl StdErr for Error {
    fn description(&self) -> &str {
        match *self {
            Error::IO(ref e) => e.description(),
            Error::Config => "there was an error parsing the configuration file",
            Error::AddrParse(ref e) => e.description(),
            Error::Parser(ref v) => {
                match v.get(0) {
                    Some(e) => e.description(),
                    None => "there was an error parsing the configuration file",
                }
            }
        }
    }

    fn cause(&self) -> Option<&StdErr> {
        match *self {
            Error::IO(ref e) => Some(e),
            Error::Config => None,
            Error::AddrParse(ref e) => Some(e),
            Error::Parser(ref v) => {
                match v.get(0) {
                    Some(e) => Some(e),
                    None => None,
                }
            }
        }
    }
}

/// Encryption Server result
type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
struct Config {
    socket: SocketAddr,
    server_log: String,
    security_log: String,
    aes_key_file: String,
}

impl Config {
    pub fn load() -> Result<Config> {
        if Path::new(CONFIG_FILE).exists() {
            let mut f = try!(fs::File::open(CONFIG_FILE));
            let mut toml = String::with_capacity(try!(f.metadata()).len() as usize);
            let _ = try!(f.read_to_string(&mut toml));

            let mut parser = Parser::new(&toml);
            let toml = match parser.parse() {
                Some(t) => t,
                None => return Err(Error::Parser(parser.errors)),
            };

            let mut logs_folder = String::new();
            let mut keys_folder = String::new();

            let now = UTC::now();
            let mut config: Config = Default::default();
            for (key, value) in toml {
                match key.as_str() {
                    "socket_address" => {
                        match value {
                            Value::String(ref socket) => {
                                config.socket = try!(SocketAddr::from_str(socket));
                            }
                            _ => return Err(Error::Config),
                        }
                    }
                    "logs_folder" => {
                        match value {
                            Value::String(ref logs_folder_config) => {
                                logs_folder = logs_folder_config.clone();
                            }
                            _ => return Err(Error::Config),
                        }
                    }
                    "keys_folder" => {
                        match value {
                            Value::String(ref keys_folder_config) => {
                                keys_folder = keys_folder_config.clone();
                            }
                            _ => return Err(Error::Config),
                        }
                    }
                    "server_log" => {
                        match value {
                            Value::String(ref server_log) => {
                                config.server_log = server_log.replace("{}", &format!("{}", now));
                            }
                            _ => return Err(Error::Config),
                        }
                    }
                    "security_log" => {
                        match value {
                            Value::String(ref security_log) => {
                                config.security_log =
                                    security_log.replace("{}", &format!("{}", now));
                            }
                            _ => return Err(Error::Config),
                        }
                    }
                    "aes_key_file" => {
                        match value {
                            Value::String(ref aes_key_file) => {
                                config.aes_key_file = aes_key_file.clone();
                            }
                            _ => return Err(Error::Config),
                        }
                    }
                    _ => return Err(Error::Config),
                }
            }

            if !keys_folder.is_empty() {
                config.aes_key_file = keys_folder.clone() + "/" + &config.aes_key_file;


                if !Path::new(&keys_folder).exists() {
                    try!(fs::create_dir_all(keys_folder));
                }
            }

            if !logs_folder.is_empty() {
                config.server_log = logs_folder.clone() + "/" + &config.server_log;
                config.security_log = logs_folder.clone() + "/" + &config.security_log;

                if !Path::new(&logs_folder).exists() {
                    try!(fs::create_dir_all(logs_folder));
                }
            }

            Ok(config)
        } else {
            Ok(Default::default())
        }
    }

    pub fn get_socket_addr(&self) -> SocketAddr {
        self.socket
    }

    pub fn get_log_file(&self) -> &Path {
        Path::new(&self.server_log)
    }

    pub fn get_security_log_file(&self) -> &Path {
        Path::new(&self.security_log)
    }

    pub fn get_aes_key_file(&self) -> &Path {
        Path::new(&self.aes_key_file)
    }
}

impl Default for Config {
    fn default() -> Config {
        let now = UTC::now();
        Config {
            socket: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), 33384)),
            server_log: format!("logs/server-{}.log", now),
            security_log: format!("logs/security-{}.log", now),
            aes_key_file: String::from("keys/aes.key"),
        }
    }
}



/// Load AES key
fn load_aes_key(config: &Config) -> Result<[u8; AES_KEY_SIZE]> {
    let mut key_file = try!(fs::File::open(config.get_aes_key_file()));
    let mut file_content = Vec::with_capacity(try!(key_file.metadata()).len() as usize);

    assert_eq!(try!(key_file.read_to_end(&mut file_content)), AES_KEY_SIZE);

    let mut key = [0u8; AES_KEY_SIZE];
    key.copy_from_slice(&file_content[..]);

    Ok(key)
}

/// Check if keys exist
fn keys_exist(config: &Config) -> bool {
    config.get_aes_key_file().exists()
}

/// Creates the server keys
fn generate_keys(config: &Config) -> Result<()> {

    let mut aes_key = [0u8; AES_KEY_SIZE];
    let mut rng = try!(OsRng::new());
    rng.fill_bytes(&mut aes_key);

    let mut aes_file = try!(fs::File::create(config.get_aes_key_file()));

    try!(aes_file.write_all(&aes_key));
    Ok(())
}

fn log<S: AsRef<str>>(config: &Config, message: S) -> Result<()> {
    let mut f = try!(fs::OpenOptions::new().append(true).create(true).open(config.get_log_file()));
    let now = UTC::now();
    try!(f.write_all(format!("{} - {}\n", now, message.as_ref()).as_bytes()));
    Ok(())
}

fn security_log<S: AsRef<str>>(config: &Config, message: S) -> Result<()> {
    let mut f =
        try!(fs::OpenOptions::new().append(true).create(true).open(config.get_security_log_file()));
    let now = UTC::now();
    try!(f.write_all(format!("{} - {}\n", now, message.as_ref()).as_bytes()));
    Ok(())
}

fn aes_key_size() -> KeySize {
    match AES_KEY_SIZE {
        16 => KeySize::KeySize128,
        24 => KeySize::KeySize192,
        32 => KeySize::KeySize256,
        _ => unreachable!(),
    }
}
