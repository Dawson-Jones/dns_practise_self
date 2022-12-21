mod byte_packet_buffer;

use std::{fs::File, io::{Read, self}};

use byte_packet_buffer::*;


fn main() -> Result<(), io::Error> {
    let mut f = File::open("response_packet.txt")?;
    let mut buffer = BytePacketBuffer::new();

    f.read(&mut buffer.buf)?;

    let packet = DnsPacket::from_buffer(&mut buffer).unwrap();
    println!("{:#?}", packet.header);

    for q in packet.questioins {
        println!("{:#?}", q);
    }

    for rec in packet.answers {
        println!("{:#?}", rec)
    }
    
    for rec in packet.authorities {
        println!("{:#?}", rec)
    }

    for rec in packet.resources {
        println!("{:#?}", rec)
    }

    Ok(())
}


// nc -u -l 1053 > query_packet.txt
// nc -u 8.8.8.8 53 < query_packet.txt > response_packet.txt


