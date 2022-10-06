use std::net::SocketAddr;
use std::net::{/*Shutdown, */TcpStream};
use std::time::{Instant/*, Duration*/};
use std::thread;
use bytestream::*;
use std::io::{Read, Write};
use std::fs::{OpenOptions, File};
//use std::sync::{Arc, mpsc, Mutex};

const MAIN_THREADS: usize = 55;
const SCANNER_THREADS: usize = 150;
const ADDRS_PER_MAIN_THREAD: usize = 0xFFFFFFFF / MAIN_THREADS;
const ADDRS_PER_SCANNER_THREAD: usize = ADDRS_PER_MAIN_THREAD / SCANNER_THREADS;
const PORT_TO_SCAN: u16 = 25565;

fn ip_to_string(ip: [u8; 4]) -> String
{
    return String::from(ip[0].to_string() + "." + ip[1].to_string().as_str() + "." + ip[2].to_string().as_str() + "." + ip[3].to_string().as_str())
}

fn try_write(buff: Vec<u8>, mut file: &File)
{
    match file.write_all(&buff)
    {
        Ok(_) => {

        },
        Err(e) => {
            println!("Failed to write to file! {:?}", e);
        }
    }
}

fn read_var_int(buf: Vec<u8>) -> i32
{
    let mut value: i32 = 0;
    let mut position: i32 = 0;
    let mut current_byte: u8;

    for item in buf
    {
        current_byte = item;
        value |= ((current_byte & 0x7F) as i32) << position;

        if (current_byte & 0x80) == 0
        {
            break;
        }

        position = position + 7;

        if position >= 32
        {
            println!("VarInt is too big!");
            return 0;
        }
    }
    return value;
}

fn write_var_int(mut buffer: Vec<u8>, mut num: i32) -> Vec<u8>
{
    loop
    {
        if (num & !0x7F) == 0
        {
            let val = num as u8;
            buffer = write_to_buffer(buffer, [val].to_vec());
            return buffer;
        }

        let val = (num as u8 & 0x7F) | 0x80;

        buffer = write_to_buffer(buffer, [val].to_vec());

        num = num >> 7;
    }

}

fn write_to_buffer(mut buf: Vec<u8>, data: Vec<u8>) -> Vec<u8>
{
    for item in data
    {
        match item.write_to(&mut buf, ByteOrder::BigEndian)
        {
            Ok(_) => continue,
            Err(e) => {
                println!("Failed to write to buffer! Error: {:?}", e);
            }
        }
    }

    return buf;
}

fn write_all_to_tcpstream(mut stream: TcpStream, buff: Vec<u8>) -> Result<TcpStream, TcpStream>
{
    match stream.write_all(&buff)
    {
        Ok(_) => {
            return Ok(stream);
        },
        Err(_) => {
            return Err(stream);
        }
    }
}

fn read_from_tcpstream(mut stream: TcpStream, buff: &mut Vec<u8>) -> Result<TcpStream, TcpStream>
{
    match stream.read(buff)
    {
        Ok(r) => {
            if r == 0
            {
                return Err(stream);
            }
            return Ok(stream);
        },
        Err(_e) => {

        }
    }

    return Ok(stream);
}
fn read_str_from_tcpstream(mut stream: TcpStream, buff: &mut String) -> Result<TcpStream, TcpStream>
{
    match stream.read_to_string(buff)
    {
        Ok(r) => {
            if r == 0
            {
                return Err(stream);
            }
            return Ok(stream);
        },
        Err(_e) => {
            
        }
    }

    return Ok(stream);
}

fn handshake(ip: [u8; 4], port: u16) -> Vec<u8>
{
    let host = ip_to_string(ip).as_bytes().to_vec();

    let mut buffer = Vec::<u8>::new();
    buffer = write_var_int(buffer, 0x00); // packet id
    buffer = write_var_int(buffer, 760); // protocol version
    buffer = write_var_int(buffer, host.len() as i32); // host len
    buffer = write_to_buffer(buffer, host); // host
    buffer = write_to_buffer(buffer, port.to_be_bytes().to_vec()); // port
    buffer = write_var_int(buffer, 1); // next state (intention)

    return buffer;
}

fn try_conn(ip: [u8; 4], tries: u8) -> bool
{
    for _ in 0..tries
    {
        let conn = TcpStream::connect(to_sock_addr(ip, PORT_TO_SCAN));
        let mut stream = match conn
        {
            Ok(r) => r,
            Err(_) => {
                continue;
            }
        };

        /*

        Minecraft Server Handshake

        */

        let mut buffer = handshake(ip, PORT_TO_SCAN);

        let c = buffer.len() as i32;

        let mut packet: Vec<u8> = vec![];

        packet = write_var_int(packet, c);

        packet.append(&mut buffer);

        stream = match write_all_to_tcpstream(stream, packet)
        {
            Ok(r) => r,
            Err(_) => continue
        };
        
        // Request Status
        let mut data: Vec<u8> = Vec::<u8>::new();
        data = write_var_int(data, 0x01);
        data = write_var_int(data, 0x00);

        stream = match write_all_to_tcpstream(stream, data)
        {
            Ok(r) => r,
            Err(_) => continue
        };

        let mut size_encoded: Vec<u8> = vec![0; 5];
        stream = match read_from_tcpstream(stream, &mut size_encoded)
        {
            Ok(r) => r,
            Err(_e) => {
                continue;
            }
        };

        let _size_i32 = read_var_int(size_encoded) as usize;
        if _size_i32 == 0 && _size_i32 < 100
        {
            continue;
        }
        
        let mut json: String = String::with_capacity(_size_i32);

        match read_str_from_tcpstream(stream, &mut json) {
            Ok(r) => r,
            Err(_e) => {
                continue;
            }
        };

        if json.len() == 0 || json.contains("400 Bad Request") || json.contains("Status 400") || json.contains("html") || json.eq("#")
        {
            continue;
        }

        println!("Found minecraft server");

        let mut file_is_valid = true;
        let mut file = None;
        match OpenOptions::new().append(true).open("results.txt")
        {
            Ok(r) => {
                file = Some(r);
            },
            Err(e) => {
                println!("Couldn't open result file! {:?}", e);
                file_is_valid = false;
            }
        };

        println!("{:?}", json);

        if file_is_valid
        {
            let results_file = file.unwrap();

            try_write(ip_to_string(ip).as_bytes().to_vec(), &results_file);
            try_write("\n".as_bytes().to_vec(), &results_file);
            try_write(json.as_bytes().to_vec(), &results_file);
            try_write("\n".as_bytes().to_vec(), &results_file);
            try_write("\n".as_bytes().to_vec(), &results_file);
        }

        if json.contains("LiveOverflow")
        {
            match File::create("LIVEOVERFLOW.txt")
            {
                Ok(mut r) => {
                    match r.write_all(json.as_bytes())
                    {
                        Ok(_) => {
                            
                        },
                        Err(e) => {
                            println!("Couldn't write to file BUT FOUND LIVEOVERFLOW! {:?}", e);
                        }
                    }
                }
                Err(e) => {
                    println!("Couldn't create file BUT FOUND LIVEOVERFLOW! {:?}", e);
                }
            }
        }
        return true;

    }

    return false;
}

fn to_sock_addr(ip_addr: [u8; 4], port: u16) -> SocketAddr
{
    SocketAddr::from((ip_addr, port))
}

fn increment_ip(mut ip_addr: [u8; 4]) -> Option<[u8; 4]>
{
    if ip_addr[3] > 254
    {
        if ip_addr[2] > 254
        {
            if ip_addr[1] > 254
            {
                if ip_addr[0] > 254
                {
                    return None;
                }
                else {
                    ip_addr[0] = ip_addr[0] + 1;
                    ip_addr[1] = 0;
                    ip_addr[2] = 0;
                    ip_addr[3] = 0;
                }
            }
            else {
                ip_addr[1] = ip_addr[1] + 1;
                ip_addr[2] = 0;
                ip_addr[3] = 0;
            }
        }
        else {
            ip_addr[2] = ip_addr[2] + 1;
            ip_addr[3] = 0;
        }
    } else {
        ip_addr[3] = ip_addr[3] + 1;
    }

    return Some(ip_addr);
}
fn add_ip(mut ip_addr: [u8; 4], to_add: usize) -> Result<[u8; 4], &'static str>
{
    for _ in 0..to_add
    {
        match increment_ip(ip_addr)
        {
            Some(r) => {
                ip_addr = r;
            },
            None => {return Err("too large") }
        }
    }

    return Ok(ip_addr);
}

fn main() {
    println!("------------------------\nMinecraft Server Scanner!\n------------------------");

    let mut handles: Vec<std::thread::JoinHandle<()>> = vec![];

    println!("Addresses per main thread: {} | Addresses per scanner thread: {}", 
        ADDRS_PER_MAIN_THREAD, ADDRS_PER_SCANNER_THREAD
    );

    let now = Instant::now();

    for i in 0..MAIN_THREADS
    {
        let mut low = [1, 1, 1, 1];
        low = match add_ip(low, ADDRS_PER_MAIN_THREAD * i)
        {
            Ok(r) => r,
            Err(_) => {
                return;
            }
        };

        println!("Thread {} starting address: {:?}", i, low);

        handles.push(thread::spawn( move || // create main threads which spawn scanner threads
        {
            let mut handles_: Vec<std::thread::JoinHandle<()>> = vec![];

            for e in 0..SCANNER_THREADS
            {
                let mut low_ = match add_ip(low, ADDRS_PER_SCANNER_THREAD * e)
                {
                    Ok(r) => r,
                    Err(_) => {
                        return;
                    }
                };

                handles_.push(std::thread::spawn(move || 
                {
                    for _ in 0..ADDRS_PER_SCANNER_THREAD
                    {
                        if low_[0] <= 10 || low_[0] == 172 || low_[0] == 192 || low_[0] >= 239
                        {
                            // invalid ip address
                            break;
                        }

                        if try_conn(low_, 1)
                        {
                            println!("Found service running at {:?}:{}", low_, PORT_TO_SCAN);
                        }

                        low_ = match increment_ip(low_)
                        {
                            Some(r) => r,
                            None => break
                        }
                    }
                }));
            }

            for item in handles_
            {
                item.join().unwrap();
            }

        }));

    }

    let mut it = 0;

    for item in handles
    {
        item.join().unwrap();
        println!("Thread {} finished", it);
        it = it + 1;
    }

    println!("Scan took {} seconds.", now.elapsed().as_secs());

    println!("Exiting...");

}
